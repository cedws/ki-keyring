package keyring

import (
	"bytes"
	"crypto/cipher"
	"fmt"

	"github.com/RyuaNerin/go-krypto/aria"
	"github.com/RyuaNerin/go-krypto/lea"
	"github.com/RyuaNerin/go-krypto/seed"
	"github.com/aead/camellia"
	"github.com/pedroalbanese/simonspeck"
)

type CipherType byte

const (
	typeSpeck64 CipherType = iota + 1
	typeAria
	typeCamellia
	typeSeed
	typeLea
)

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
	}

	return ""
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
