package picocryption

import (
	"crypto/cipher"
	"io"

	"golang.org/x/crypto/chacha20"
)

type nonceManager struct {
	chachaNonces [][24]byte
	serpentIVs   [][16]byte
	hkdf         io.Reader
}

func (nm *nonceManager) extendTo(i int) error {
	for i >= len(nm.chachaNonces) {
		chachaNonce := [24]byte{}
		serpentIV := [16]byte{}
		_, err := io.ReadFull(nm.hkdf, chachaNonce[:])
		if err != nil {
			return err
		}
		_, err = io.ReadFull(nm.hkdf, serpentIV[:])
		if err != nil {
			return err
		}
		nm.chachaNonces = append(nm.chachaNonces, chachaNonce)
		nm.serpentIVs = append(nm.serpentIVs, serpentIV)
	}
	return nil
}

func (nm *nonceManager) chachaNonce(i int) ([24]byte, error) {
	err := nm.extendTo(i)
	if err != nil {
		return [24]byte{}, err
	}
	return nm.chachaNonces[i], nil
}

func (nm *nonceManager) serpentIV(i int) ([16]byte, error) {
	err := nm.extendTo(i)
	if err != nil {
		return [16]byte{}, err
	}
	return nm.serpentIVs[i], nil
}

func newNonceManager(keys keys) *nonceManager {
	nm := &nonceManager{
		hkdf:         keys.hkdf,
		chachaNonces: [][24]byte{keys.seeds.nonce},
		serpentIVs:   [][16]byte{keys.seeds.serpentIV},
	}
	return nm
}

type serpentCipher struct {
	serpentBlock cipher.Block
	cipher       cipher.Stream
	nonceManager *nonceManager
	header       *header
}

func (sc *serpentCipher) reset(i int) error {
	serpentIV, err := sc.nonceManager.serpentIV(i)
	if err != nil {
		return err
	}
	sc.cipher = cipher.NewCTR(sc.serpentBlock, serpentIV[:])
	return nil
}

func (sc *serpentCipher) xor(p []byte) error {
	if sc.header.settings.Paranoid {
		sc.cipher.XORKeyStream(p, p)
	}
	return nil
}

type chachaCipher struct {
	cipher       *chacha20.Cipher
	nonceManager *nonceManager
	key          []byte
}

func (cc *chachaCipher) reset(i int) error {
	nonce, err := cc.nonceManager.chachaNonce(i)
	if err != nil {
		return err
	}
	cc.cipher, err = chacha20.NewUnauthenticatedCipher(cc.key[:], nonce[:])
	return err
}

func (cc *chachaCipher) xor(p []byte) error {
	cc.cipher.XORKeyStream(p, p)
	return nil
}

type xorCipher interface {
	xor(p []byte) error
	reset(i int) error
}

type rotatingCipher struct {
	xorCipher
	writtenCounter int64
	resetCounter   int
	initialised    bool
}

func (rc *rotatingCipher) stream(p []byte) ([]byte, bool, error) {
	if !rc.initialised {
		err := rc.reset(0)
		if err != nil {
			return nil, false, err
		}
		rc.initialised = true
	}
	i := int64(0)
	for i < int64(len(p)) {
		j := min(int64(len(p))-i, resetNonceAt-rc.writtenCounter)
		err := rc.xor(p[i : i+j])
		if err != nil {
			return nil, false, err
		}
		rc.writtenCounter += j
		if rc.writtenCounter == resetNonceAt {
			rc.writtenCounter = 0
			rc.resetCounter++
			err = rc.reset(rc.resetCounter)
			if err != nil {
				return nil, false, err
			}
		}
		i += j
	}
	return p, false, nil
}

func (rc *rotatingCipher) flush() ([]byte, bool, error) {
	return nil, false, nil
}
