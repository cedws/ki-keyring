package scan

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type PatternError struct {
	Err string
}

func (e *PatternError) Error() string {
	return fmt.Sprintf("invalid pattern: %v", e.Err)
}

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
		return nil, &PatternError{"must be whole bytes, not nibbles"}
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
			return &PatternError{fmt.Sprintf("invalid byte %v at position %v", token, i)}
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
