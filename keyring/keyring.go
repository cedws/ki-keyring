package keyring

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cedws/ki-keyring/scan"
	peparser "github.com/saferwall/pe"
	"golang.org/x/arch/x86/x86asm"
)

const (
	initSignature = "48 83 ?? ?? 41 b8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 83 ?? ?? e9"
	keyCount      = 5
)

var initPattern = scan.MustParse(initSignature)

type Key struct {
	Operand       byte   `json:"operand"`
	Cipher        string `json:"cipher"`
	DecryptionKey []byte `json:"decryptionKey"`
	DecryptionIV  []byte `json:"decryptionIV"`
	Public        []byte `json:"public"`
	Private       []byte `json:"private"`
}

type Keyring struct {
	Raw     []byte        `json:"raw"`
	Decoded [keyCount]Key `json:"decoded"`
}

func (k Key) MarshalBinary() ([]byte, error) {
	var cipher CipherType
	if err := cipher.Parse(k.Cipher); err != nil {
		return nil, err
	}

	obfuscated := make([]byte, len(k.Public))
	copy(obfuscated, k.Public)

	// XOR the public key with the desired operand pre-encryption
	for i, b := range obfuscated {
		obfuscated[i] = b ^ byte(k.Operand)
	}

	ciphertext, err := encrypt(cipher, k.DecryptionKey, k.DecryptionIV, obfuscated)
	if err != nil {
		return nil, err
	}

	var buf []byte

	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(k.DecryptionKey)+len(k.DecryptionIV)+len(ciphertext)+2))
	buf = append(buf, byte(cipher))
	buf = append(buf, k.DecryptionKey...)
	buf = append(buf, k.DecryptionIV...)
	buf = binary.LittleEndian.AppendUint16(buf, uint16(len(obfuscated)))
	buf = append(buf, ciphertext...)

	return buf, nil
}

func (k *Key) UnmarshalBinary(buf []byte) error {
	if len(buf) < 34 {
		return errors.New("buffer too short")
	}
	cipher := CipherType(buf[2])
	buf = buf[3:]

	var decryptionKey, decryptionIV, ciphertext []byte
	var keylen uint16

	switch cipher {
	case typeSpeck64:
		decryptionKey, decryptionIV = buf[0:12], buf[12:20]
		keylen = binary.LittleEndian.Uint16(buf[20:22])
		ciphertext = buf[22:]
	default:
		decryptionKey, decryptionIV = buf[0:16], buf[16:32]
		keylen = binary.LittleEndian.Uint16(buf[32:34])
		ciphertext = buf[34:]
	}

	decrypted, err := decrypt(cipher, decryptionKey, decryptionIV, ciphertext)
	if err != nil {
		return err
	}

	operand := decrypted[0] ^ 0x30
	if decrypted[1]^0x82 != operand {
		return errors.New("failed to guess XOR operand")
	}
	for i, b := range decrypted {
		decrypted[i] = b ^ byte(operand)
	}

	if _, err := x509.ParsePKIXPublicKey(decrypted[:keylen]); err != nil {
		return err
	}

	*k = Key{
		operand,
		cipher.String(),
		decryptionKey,
		decryptionIV,
		decrypted[:keylen],
		nil,
	}

	return nil
}

// Extract extracts the keyring from a given game client.
func Extract(gameData []byte) (*Keyring, error) {
	rawKeys, err := findRawKeys(gameData)
	if err != nil {
		return nil, err
	}

	if len(rawKeys) < 1 {
		return nil, fmt.Errorf("raw key buffer too short")
	}

	kr := Keyring{
		Raw: rawKeys,
	}
	rawKeys = rawKeys[1:]

	for i := range kr.Decoded {
		length := 3 + binary.LittleEndian.Uint16(rawKeys[:2])

		if err := kr.Decoded[i].UnmarshalBinary(rawKeys[:length]); err != nil {
			return nil, err
		}

		rawKeys = rawKeys[length:]
	}

	return &kr, nil
}

func (k *Keyring) Regenerate() error {
	for i := range k.Decoded {
		keypair, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return err
		}

		pub, err := x509.MarshalPKIXPublicKey(keypair.Public())
		if err != nil {
			return err
		}
		k.Decoded[i].Public = pub

		priv, err := x509.MarshalPKCS8PrivateKey(keypair)
		if err != nil {
			return err
		}
		k.Decoded[i].Private = priv
	}

	return nil
}

// Inject injects a keyring into a given game client and returns the modified client.
func (kr *Keyring) Inject(gameData []byte) ([]byte, error) {
	rawKeys, err := findRawKeys(gameData)
	if err != nil {
		return nil, err
	}

	if len(rawKeys) < 1 {
		return nil, fmt.Errorf("raw key buffer too short")
	}
	rawKeys = rawKeys[1:]

	var buf []byte
	for _, key := range kr.Decoded {
		bytes, err := key.MarshalBinary()
		if err != nil {
			return nil, err
		}

		buf = append(buf, bytes...)
	}

	if len(rawKeys) != len(buf) {
		panic(fmt.Sprintf("unexpected length diff between original and new key buffer (%v => %v)", len(rawKeys), len(buf)))
	}
	copy(rawKeys, buf)

	return gameData, nil
}

func findRawKeys(gameData []byte) ([]byte, error) {
	pe, err := peparser.NewBytes(gameData, &peparser.Options{Fast: true})
	if err != nil {
		return nil, err
	}

	if err := pe.Parse(); err != nil {
		return nil, err
	}

	for _, result := range initPattern.Scan(gameData) {
		addr := result

		inst, _ := x86asm.Decode(gameData[addr:], 64)
		addr = addr + uint64(inst.Len)

		inst, _ = x86asm.Decode(gameData[addr:], 64)
		addr = addr + uint64(inst.Len)

		length := inst.Args[1].(x86asm.Imm)
		// roughly the minimum size all keys can be fit into
		if length < (keyCount * 256) {
			continue
		}

		inst, _ = x86asm.Decode(gameData[addr:], 64)
		addr = addr + uint64(inst.Len)

		operand := inst.Args[1].(x86asm.Mem).Disp

		start := 0xc00 + pe.GetOffsetFromRva(uint32(addr)+uint32(operand))
		end := start + uint32(length)

		// just additional validation that we've found the right address
		if len(gameData) >= int(start) && gameData[start] == 0x35 {
			return gameData[start:end:end], nil
		}
	}

	return nil, errors.New("failed to locate keyring in game client")
}
