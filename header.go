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
	data = append(data, header.seeds.Salt[:])
	data = append(data, header.seeds.HkdfSalt[:])
	data = append(data, header.seeds.SerpentIV[:])
	data = append(data, header.seeds.Nonce[:])
	data = append(data, header.refs.keyRef[:])
	data = append(data, header.refs.keyfileRef[:])
	data = append(data, header.refs.macTag[:])

	headerBytes := make([]byte, baseHeaderSize+3*len(header.settings.Comments))
	written := 0
	for _, d := range data {
		err := rsEncode(headerBytes[written:written+len(d)*3], d)
		if err != nil {
			return nil, err
		}
		written += len(d) * 3
	}

	if header.settings.Deniability {
		denyStream := newDeniabilityStream(password, header)
		var err error
		headerBytes, err = denyStream.stream(headerBytes)
		if err != nil {
			return nil, fmt.Errorf("denying header data: %w", err)
		}
		headerBytes = append(append(header.seeds.DenySalt[:], header.seeds.DenyNonce[:]...), headerBytes...)
	}

	return headerBytes, nil
}
