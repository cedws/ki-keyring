package client

import (
	"crypto/cipher"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/RyuaNerin/go-krypto/seed"
	"github.com/aead/camellia"
	"github.com/pedroalbanese/simonspeck"
)

const initSignature = "48 83 ?? ?? 41 b8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8d ?? ?? ?? ?? ?? 48 83 ?? ?? e9"
const keyCount = 5

type CipherType byte

const (
	typeSpeck64 CipherType = iota + 1
	typeAria
	typeCamellia
	typeSeed
	typeLea
)

type GameClient struct {
	file *os.File
}

func (c CipherType) String() string {
	switch c {
	case typeSpeck64:
		return "SPECK_64"
	case typeAria:
		return "ARIA"
	case typeCamellia:
		return "CAMELLIA"
	case typeSeed:
		return "SEED"
	case typeLea:
		return "LEA"
	default:
		panic("unknown algorithm for key")
	}
}

func (c *CipherType) Parse(s string) error {
	switch s {
	case "SPECK_64":
		*c = typeSpeck64
	case "ARIA":
		*c = typeAria
	case "CAMELLIA":
		*c = typeCamellia
	case "SEED":
		*c = typeSeed
	case "LEA":
		*c = typeLea
	default:
		return fmt.Errorf("invalid symmetric algorithm %v", s)
	}

	return nil
}

func toCipher(cipherType CipherType, key []byte) (c cipher.Block, err error) {
	switch cipherType {
	case typeSpeck64:
		c = simonspeck.NewSpeck64(key)
	case typeAria:
		c, err = aria.NewCipher(key)
	case typeCamellia:
		c, err = camellia.NewCipher(key)
	case typeSeed:
		c, err = seed.NewCipher(key)
	case typeLea:
		c, err = lea.NewCipher(key)
	default:
		panic("unknown algorithm for key")
	}

	return
}

func Open(clientPath string) (*GameClient, error) {
	file, err := os.OpenFile(clientPath, os.O_RDWR, 0o755)
	if err != nil {
		return nil, err
	}

	return &GameClient{
		file,
	}, nil
}

func (g *GameClient) Close() error {
	return g.file.Close()
}

func (g *GameClient) KeyBuffer() ([]byte, error) {
	g.file.Seek(0, io.SeekStart)

	data, err := ioutil.ReadAll(g.file)
	if err != nil {
		return nil, err
	}

	original, err := locateKeys(data)
	if err != nil {
		return nil, fmt.Errorf("client: while locating keys: %w", err)
	}

	return original, nil
}

func (g *GameClient) Keys() (Keys, error) {
	g.file.Seek(0, io.SeekStart)

	data, err := ioutil.ReadAll(g.file)
	if err != nil {
		return nil, err
	}

	buf, err := locateKeys(data)
	if err != nil {
		return nil, err
	}

	keys := make(Keys, keyCount)
	if err := keys.UnmarshalBinary(buf[1:]); err != nil {
		return nil, err
	}

	return keys, nil
}

func (g *GameClient) WriteKeys(keys Keys) error {
	g.file.Seek(0, io.SeekStart)

	data, err := ioutil.ReadAll(g.file)
	if err != nil {
		return err
	}

	original, err := locateKeys(data)
	if err != nil {
		return err
	}
	// first byte is not relevant
	original = original[1:]

	buf, err := keys.MarshalBinary()
	if err != nil {
		return err
	}

	if len(buf) != len(original) {
		panic(fmt.Sprintf("unexpected length diff between original and new key buffer (%v => %v)", len(original), len(buf)))
	}
	copy(original, buf)

	g.file.Seek(0, io.SeekStart)
	_, err = g.file.Write(data)

	return err
}
