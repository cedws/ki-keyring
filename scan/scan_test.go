package scan

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestChunksValid(t *testing.T) {
	s := "12345678"

	err := chunks(s, 2, func(i int, token string) (err error) {
		if i == 0 {
			assert.Equal(t, "12", token)
		}

		if i == 4 {
			assert.Equal(t, "78", token)
		}

		return
	})
	assert.Nil(t, err)

	err = chunks(s, 4, func(i int, token string) (err error) {
		if i == 0 {
			assert.Equal(t, "1234", token)
		}

		if i == 1 {
			assert.Equal(t, "5678", token)
		}

		return
	})
	assert.Nil(t, err)
}

func TestChunksError(t *testing.T) {
	s := "12345678"
	err := chunks(s, 2, func(i int, token string) (err error) {
		if i == 3 {
			return errors.New("")
		}
		return
	})
	assert.NotNil(t, err)
}

func TestParseValidSpaced(t *testing.T) {
	sig := "01 02 03 04 ?? 06 07 08 09 0A 0B 0C 0D 0E 0F"
	p, err := Parse(sig)
	assert.Nil(t, err)
	assert.Equal(t, 15, len(p.pattern))
	assert.Equal(t, 15, len(p.mask))
	assert.Equal(t, true, p.mask[4])
}

func TestParseValidUnspaced(t *testing.T) {
	sig := "0102030405060708??0A0B0C0D0E0F"
	p, err := Parse(sig)
	assert.Nil(t, err)
	assert.Equal(t, 15, len(p.pattern))
	assert.Equal(t, 15, len(p.mask))
	assert.Equal(t, true, p.mask[8])
}

func TestParseInvalid(t *testing.T) {
	sig := "01020304?!060708090A0B0C0D0E0F1011"
	_, err := Parse(sig)
	assert.NotNil(t, err)
}
