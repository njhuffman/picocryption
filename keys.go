package picocryption

import (
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

type seeds struct {
	salt      [16]byte
	nonce     [24]byte
	serpentIV [16]byte
	hkdfSalt  [32]byte
	denySalt  [16]byte
	denyNonce [24]byte
}

type keys struct {
	settings     Settings
	key          [32]byte
	macKey       [32]byte
	serpentKey   [32]byte
	denyKey      [32]byte
	hkdf         io.Reader
	keyRef       [64]byte
	keyfileRef   [32]byte
}

func xor(a, b [32]byte) [32]byte {
	var result [32]byte
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

func generateKeyfileKey(ordered bool, keyfiles []io.Reader) ([32]byte, error) {
	var key [32]byte

	if len(keyfiles) == 0 {
		return key, nil
	}

	hashes := make([][32]byte, len(keyfiles))
	hasher := sha3.New256()
	for i, file := range keyfiles {
		if err := hashKeyfile(file, hasher, hashes[i][:]); err != nil {
			return key, err
		}
		if !ordered {
			hasher.Reset()
		}
	}

	if ordered {
		copy(key[:], hasher.Sum(nil))
		return key, nil
	}

	key = combineHashes(hashes)
	if hasDuplicates(hashes) {
		return key, ErrDuplicateKeyfiles
	}

	return key, nil
}

func hashKeyfile(reader io.Reader, hasher hash.Hash, hashBuf []byte) error {
	buf, err := io.ReadAll(reader)
	if err != nil {
		return fmt.Errorf("reading keyfile: %w", err)
	}
	hasher.Write(buf)
	copy(hashBuf, hasher.Sum(nil))
	return nil
}

func combineHashes(hashes [][32]byte) [32]byte {
	var combined [32]byte
	for _, hash := range hashes {
		combined = xor(combined, hash)
	}
	return combined
}

func hasDuplicates(hashes [][32]byte) bool {
	hashSet := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		hashStr := string(hash[:])
		if _, exists := hashSet[hashStr]; exists {
			return true
		}
		hashSet[hashStr] = struct{}{}
	}
	return false
}

func generatePasswordKey(password string, salt [16]byte, paranoid bool) [32]byte {
	var key [32]byte
	iterations := uint32(4)
	parallelism := uint8(4)
	if paranoid {
		iterations = 8
		parallelism = 8
	}
	copy(key[:], argon2.IDKey([]byte(password), salt[:], iterations, 1<<20, parallelism, 32))
	return key
}

func generateDenyKey(password string, salt [16]byte) [32]byte {
	var key [32]byte
	copy(key[:], argon2.IDKey([]byte(password), salt[:], 4, 1<<20, 4, 32))
	return key
}

func newKeys(settings Settings, seeds seeds, password string, keyfiles []io.Reader) (keys, error) {
	keyfileKey, err := generateKeyfileKey(settings.OrderedKf, keyfiles)
	if err != nil && !errors.Is(err, ErrDuplicateKeyfiles) {
		return keys{}, fmt.Errorf("creating keys: %w", err)
	}
	duplicateKeyfiles := errors.Is(err, ErrDuplicateKeyfiles)

	passwordKey := generatePasswordKey(password, seeds.salt, settings.Paranoid)

	var keyRef [64]byte
	err = computeHash(sha3.New512(), passwordKey[:], keyRef[:])
	if err != nil {
		return keys{}, fmt.Errorf("creating keys: %w", err)
	}
	var keyfileRef [32]byte
	if len(keyfiles) > 0 {
		computeHash(sha3.New256(), keyfileKey[:], keyfileRef[:])
	}

	key := xor(keyfileKey, passwordKey)

	var denyKey [32]byte
	if settings.Deniability {
		denyKey = generateDenyKey(password, seeds.denySalt)
	}

	hkdf := hkdf.New(sha3.New256, key[:], seeds.hkdfSalt[:], nil)
	macKey, err := readFromHkdf(hkdf)
	if err != nil {
		return keys{}, err
	}
	serpentKey, err := readFromHkdf(hkdf)
	if err != nil {
		return keys{}, err
	}

	keys := keys{
		settings:     settings,
		key:          key,
		macKey:       macKey,
		serpentKey:   serpentKey,
		denyKey:      denyKey,
		hkdf:         hkdf,
		keyRef:       keyRef,
		keyfileRef:   keyfileRef,
	}

	if duplicateKeyfiles {
		return keys, ErrDuplicateKeyfiles
	}
	return keys, nil
}

func computeHash(hasher hash.Hash, data []byte, dest []byte) error {
	_, err := hasher.Write(data)
	if err != nil {
		return err
	}
	copy(dest, hasher.Sum(nil))
	return nil
}

func readFromHkdf(hkdf io.Reader) ([32]byte, error) {
	var key [32]byte
	if _, err := hkdf.Read(key[:]); err != nil {
		return key, fmt.Errorf("reading hkdf: %w", err)
	}
	return key, nil
}

func randomSeeds() (seeds, error) {
	var seeds seeds
	fields := [][]byte{
		seeds.denyNonce[:],
		seeds.denySalt[:],
		seeds.hkdfSalt[:],
		seeds.nonce[:],
		seeds.salt[:],
		seeds.serpentIV[:],
	}
	for _, field := range fields {
		if _, err := rand.Read(field); err != nil {
			return seeds, err
		}
	}
	return seeds, nil
}
