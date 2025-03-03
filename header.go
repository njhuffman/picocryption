package picocryption

import (
	"fmt"
)

const (
	baseHeaderSize = 789
	versionSize    = 5
	commentSize    = 5
	flagsSize      = 5
)

type refs struct {
	keyRef     [64]byte
	keyfileRef [32]byte
	macTag     [64]byte
}

type header struct {
	settings Settings
	seeds    seeds
	refs     refs
	usesKf   bool
	fileSize int64
}

func (header *header) size() int {
	size := baseHeaderSize + 3*len(header.settings.Comments)
	if header.settings.Deniability {
		size += len(header.seeds.denySalt)
		size += len(header.seeds.denyNonce)
	}
	return size
}

func (header *header) bytes(password string) ([]byte, error) {
	data := [][]byte{[]byte(picocryptVersion)}
	data = append(data, []byte(fmt.Sprintf("%05d", len(header.settings.Comments))))
	for _, c := range []byte(header.settings.Comments) {
		data = append(data, []byte{c})
	}
	flags := []bool{
		header.settings.Paranoid,
		header.usesKf,
		header.settings.OrderedKf,
		header.settings.ReedSolomon,
		header.fileSize%(1<<20) > (1<<20)-chunkSize,
	}
	flagBytes := make([]byte, len(flags))
	for i, f := range flags {
		if f {
			flagBytes[i] = 1
		}
	}
	data = append(data, flagBytes)
	data = append(data, header.seeds.salt[:])
	data = append(data, header.seeds.hkdfSalt[:])
	data = append(data, header.seeds.serpentIV[:])
	data = append(data, header.seeds.nonce[:])
	data = append(data, header.refs.keyRef[:])
	data = append(data, header.refs.keyfileRef[:])
	data = append(data, header.refs.macTag[:])

	headerBytes := make([]byte, header.size())
	written := 0
	for _, d := range data {
		err := rsEncode(headerBytes[written:written+len(d)*3], d)
		if err != nil {
			return nil, err
		}
		written += len(d) * 3
	}

	if header.settings.Deniability {
		denyKey := generateDenyKey(password, header.seeds.denySalt)
		deny, err := newDeniability(denyKey, header.seeds.denyNonce, header.seeds.denySalt, 0)
		if err != nil {
			return nil, fmt.Errorf("creating deniability cipher: %w", err)
		}
		deny.deny(headerBytes)
		headerBytes = append(append(headerBytes, deny.salt[:]...), deny.nonce[:]...)
	}

	return headerBytes, nil
}
