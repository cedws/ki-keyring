package client

import (
	"bytes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/cedws/pubkey-extract/scan"
	peparser "github.com/saferwall/pe"
	log "github.com/sirupsen/logrus"
	"golang.org/x/arch/x86/x86asm"
)

var (
	ErrPubkeyLocation  = errors.New("client: failed to locate pubkey buffer in game client")
	ErrSectionNotFound = errors.New("client: failed to find .data section")
)

var initPattern *scan.Pattern

type Key struct {
	Operand       int
	Cipher        string
	DecryptionKey []byte
	DecryptionIV  []byte
	Public        []byte
	Private       []byte
}

type Keys []Key

func init() {
	initPattern = scan.MustParse(initSignature)
}

func getRawToVirtualOffset(data []byte) (uint64, error) {
	pe, err := peparser.NewBytes(data, &peparser.Options{Fast: true})
	if err != nil {
		return 0, err
	}

	if err = pe.Parse(); err != nil {
		return 0, err
	}

	for _, section := range pe.Sections {
		sectionName := string(section.Header.Name[:])

		if strings.HasPrefix(sectionName, ".data") {
			return (uint64(section.Header.PointerToRawData) - uint64(section.Header.VirtualAddress)) + 0xc00, nil
		}
	}

	return 0, ErrSectionNotFound
}

func locateKeys(data []byte) (buf []byte, err error) {
	rvo, err := getRawToVirtualOffset(data)
	if err != nil {
		return nil, err
	}

	for _, result := range initPattern.Scan(data) {
		var inst x86asm.Inst

		addr := result

		inst, _ = x86asm.Decode(data[addr:], 64)
		addr = addr + uint64(inst.Len)

		inst, _ = x86asm.Decode(data[addr:], 64)
		addr = addr + uint64(inst.Len)

		length := inst.Args[1].(x86asm.Imm)
		// roughly the minimum size all five keys can be fit into
		if length < 0x5b4 {
			continue
		}

		log.Debugf("key buffer length is %v", length)

		inst, _ = x86asm.Decode(data[addr:], 64)
		addr = addr + uint64(inst.Len)

		operand := inst.Args[1].(x86asm.Mem).Disp
		ptr := addr + rvo + uint64(operand)

		// just additional validation that we've found the right address
		if data[ptr] == 0x35 {
			buf = data[ptr : ptr+uint64(length)]
			return
		}
	}

	return nil, ErrPubkeyLocation
}

func deobfuscateXOR(buf []byte) int {
	var operand int

	for operand <= 0xFF {
		// keep guessing XOR operand by looking for start of ASN.1 structure
		if buf[0]^byte(operand) == 0x30 && buf[1]^byte(operand) == 0x82 {
			break
		}
		operand++
	}

	if operand > 0xFF {
		log.Error("failed to guess XOR operand")
		return 0
	}

	log.Debugf("using %v as XOR operand", operand)

	for i, b := range buf {
		buf[i] = b ^ byte(operand)
	}

	return operand
}

func (keys Keys) MarshalBinary() (buf []byte, err error) {
	for _, key := range keys {
		var cipher CipherType
		if err := cipher.Parse(key.Cipher); err != nil {
			return nil, fmt.Errorf("client: while marshaling: %w", err)
		}

		obfuscated := make([]byte, len(key.Public))
		copy(obfuscated, key.Public)

		// XOR the public key with the desired operand pre-encryption
		for i, b := range obfuscated {
			obfuscated[i] = b ^ byte(key.Operand)
		}

		ciphertext, err := encrypt(cipher, key.DecryptionKey, key.DecryptionIV, obfuscated)
		if err != nil {
			return nil, fmt.Errorf("client: while marshaling: %w", err)
		}

		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(key.DecryptionKey)+len(key.DecryptionIV)+len(ciphertext)+2))
		buf = append(buf, byte(cipher))
		buf = append(buf, key.DecryptionKey...)
		buf = append(buf, key.DecryptionIV...)
		buf = binary.LittleEndian.AppendUint16(buf, uint16(len(obfuscated)))
		buf = append(buf, ciphertext...)
	}

	return
}

func (keys *Keys) UnmarshalBinary(bytes []byte) error {
	for i := range *keys {
		length := 3 + binary.LittleEndian.Uint16(bytes[0:2])
		cipher := CipherType(bytes[2])

		buf := bytes[3:length]

		key, iv := buf[0:16], buf[16:32]
		keylen := binary.LittleEndian.Uint16(buf[32:34])
		ciphertext := buf[34:]

		if cipher == typeSpeck64 {
			key, iv = buf[0:12], buf[12:20]
			keylen = binary.LittleEndian.Uint16(buf[20:22])
			ciphertext = buf[22:]
		}

		buf, err := decrypt(cipher, key, iv, ciphertext)
		if err != nil {
			return fmt.Errorf("client: while unmarshaling: %w", err)
		}

		// iteratively find the XOR operand needed to reveal the ASN.1 structure
		operand := deobfuscateXOR(buf)

		if _, err = x509.ParsePKIXPublicKey(buf[:keylen]); err != nil {
			return fmt.Errorf("client: while unmarshaling: %w", err)
		}

		(*keys)[i] = Key{
			operand,
			cipher.String(),
			key,
			iv,
			buf[:keylen],
			nil,
		}

		bytes = bytes[length:]
	}

	return nil
}

func encrypt(cipherType CipherType, key []byte, iv []byte, buf []byte) (dst []byte, err error) {
	c, err := toCipher(cipherType, key)
	if err != nil {
		return
	}

	pad := c.BlockSize() - len(buf)%c.BlockSize()
	buf = append(buf, bytes.Repeat([]byte{0x0}, pad)...)
	dst = make([]byte, len(buf))

	mode := cipher.NewCBCEncrypter(c, iv)
	mode.CryptBlocks(dst, buf)

	return
}

func decrypt(cipherType CipherType, key []byte, iv []byte, buf []byte) (dst []byte, err error) {
	c, err := toCipher(cipherType, key)
	if err != nil {
		return
	}

	dst = make([]byte, len(buf))

	mode := cipher.NewCBCDecrypter(c, iv)
	mode.CryptBlocks(dst, buf)

	return
}
