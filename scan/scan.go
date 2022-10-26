package scan

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrInvalidLength = errors.New("invalid pattern length")
)

type Pattern struct {
	mask    []bool
	pattern []byte
}

func MustParse(pattern string) *Pattern {
	if p, err := Parse(pattern); err != nil {
		panic(err)
	} else {
		return p
	}
}

func Parse(pattern string) (*Pattern, error) {
	pattern = strings.ReplaceAll(pattern, " ", "")

	if len(pattern)%2 != 0 {
		return nil, ErrInvalidLength
	}

	p := Pattern{
		mask:    make([]bool, len(pattern)/2),
		pattern: make([]byte, len(pattern)/2),
	}

	err := chunks(pattern, 2, func(i int, token string) (err error) {
		if token == "??" {
			p.mask[i] = true
			return
		}

		byt, err := hex.DecodeString(token)
		if err != nil {
			return fmt.Errorf("invalid byte in pattern: %v", token)
		}

		if len(byt) != 1 {
			panic("unexpected len after decoding byte")
		}

		p.pattern[i] = byt[0]

		return
	})

	return &p, err
}

func (p *Pattern) Scan(buf []byte) []uint64 {
	var results []uint64

Outer:
	for i := 0; i < len(buf); i++ {
		for n, b := range p.pattern {
			if b != buf[i+n] && !p.mask[n] {
				i += n
				continue Outer
			}
		}

		results = append(results, uint64(i))
	}

	return results
}

func chunks(s string, size uint, f func(int, string) error) error {
	for i := uint(0); i < uint(len(s))/size; i++ {
		if err := f(int(i), s[i*size:i*size+size]); err != nil {
			return err
		}
	}

	return nil
}
