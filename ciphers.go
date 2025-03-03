package picocryption

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/sha3"
)

const resetNonceAt = int64(60 * (1 << 30))

func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

type deniability struct {
	key     [32]byte
	salt    [16]byte
	nonce   [24]byte
	chacha  *chacha20.Cipher
	counter int64
}

func (deny *deniability) deny(p []byte) error {
	i := int64(0)
	for i < int64(len(p)) {
		j := min(int64(len(p))-i, resetNonceAt-deny.counter)
		deny.chacha.XORKeyStream(p[i:i+j], p[i:i+j])
		err := deny.updateCounter(j)
		if err != nil {
			return fmt.Errorf("updating deniability counter: %w", err)
		}
		i += j
	}
	return nil
}

func (deny *deniability) updateCounter(length int64) error {
	deny.counter += length
	if deny.counter < resetNonceAt {
		return nil
	}
	if deny.counter > resetNonceAt {
		return errors.New("overshot counter target")
	}
	tmp := sha3.New256()
	_, err := tmp.Write(deny.nonce[:])
	if err != nil {
		return fmt.Errorf("writing new nonce: %w", err)
	}
	copy(deny.nonce[:], tmp.Sum(nil))
	deny.chacha, err = chacha20.NewUnauthenticatedCipher(deny.key[:], deny.nonce[:])
	if err != nil {
		return fmt.Errorf("creating chacha cipher: %w", err)
	}
	deny.counter = 0
	return nil
}

func newDeniability(key [32]byte, nonce [24]byte, salt [16]byte, offset int) (*deniability, error) {
	chacha, err := chacha20.NewUnauthenticatedCipher(key[:], nonce[:])
	if err != nil {
		return nil, fmt.Errorf("creating chacha cipher: %w", err)
	}
	deny := &deniability{
		key:     key,
		salt:    salt,
		nonce:   nonce,
		chacha:  chacha,
		counter: 0,
	}
	tmp := make([]byte, offset)
	deny.deny(tmp)
	return deny, nil
}
