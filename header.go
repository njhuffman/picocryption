package picocryption

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const (
	baseHeaderSize = 789
	versionSize    = 5
	commentSize    = 5
	flagsSize      = 5
)

type header struct {
	settings Settings
	seeds    seeds
	refs     refs
	usesKf   bool
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
		false, // TODO need to implement this
		// header.fileSize%(1<<20) > (1<<20)-chunkSize,
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

func readVersion(reader io.Reader, password string) (*deniability, bool, error) {
	raw := make([]byte, versionSize*3)
	n, err := io.ReadFull(reader, raw)
	if n == 0 || errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, false, ErrFileTooShort
	}
	if err != nil {
		return nil, false, err
	}

	version := make([]byte, versionSize)
	damaged, rsErr := rsDecode(version, raw, false)
	valid, rgErr := regexp.Match(`^v1\.\d{2}`, []byte(version))
	if rgErr != nil {
		return nil, damaged, fmt.Errorf("parsing version format: %w", rgErr)
	}
	if (rsErr == nil) && valid {
		return nil, damaged, nil
	}

	// parsing version failed, assume deniability mode
	var salt [16]byte
	var nonce [24]byte
	tmp := make([]byte, len(salt)+len(nonce))
	copy(tmp, raw)
	_, err = io.ReadFull(reader, tmp[len(raw):])
	if err != nil {
		return nil, false, err
	}
	copy(salt[:], tmp[:len(salt)])
	copy(nonce[:], tmp[len(salt):])

	deny, err := newDeniability(generateDenyKey(password, salt), nonce, salt, 0)
	if err != nil {
		return nil, false, fmt.Errorf("creating deniability cipher: %w", err)
	}
	raw = make([]byte, versionSize*3)
	_, err = io.ReadFull(reader, raw)
	if err != nil {
		return nil, false, err
	}
	err = deny.deny(raw)
	if err != nil {
		return nil, false, err
	}
	version = make([]byte, versionSize)
	damaged, err = rsDecode(version, raw, false)
	if err != nil {
		return nil, damaged, err
	}
	valid, _ = regexp.Match(`^v1\.\d{2}`, []byte(version))
	if !valid {
		return nil, true, ErrCorrupted
	}
	return deny, damaged, nil
}

func readFromHeader(reader io.Reader, size int, deny *deniability) ([]byte, bool, error) {
	if size == 0 {
		return []byte{}, false, nil
	}
	tmp := make([]byte, size*3)
	n, err := io.ReadFull(reader, tmp)
	tmp = tmp[:n]
	if deny != nil {
		denyErr := deny.deny(tmp)
		if denyErr != nil {
			return tmp, false, denyErr
		}
	}
	if err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return tmp, false, ErrFileTooShort
		}
		return tmp, false, err
	}
	data := make([]byte, size)
	damaged, err := rsDecode(data, tmp, false)
	if errors.Is(err, ErrCorrupted) {
		return tmp, damaged, err
	}
	return data, damaged, err
}

func readHeader(reader io.Reader, password string) (header, bool, error) {
	deny, damaged, err := readVersion(reader, password)
	if err != nil {
		return header{}, damaged, fmt.Errorf("reading version: %w", err)
	}

	cLen, dmg, err := readFromHeader(reader, commentSize, deny)
	if dmg {
		damaged = true
	}
	if err != nil {
		return header{}, damaged, fmt.Errorf("reading comment length: %w", err)
	}
	c, err := strconv.Atoi(string(cLen))
	if err != nil {
		return header{}, damaged, fmt.Errorf("parsing comment length: %w", err)
	}
	var builder strings.Builder
	for i := 0; i < c; i++ {
		n, dmg, err := readFromHeader(reader, 1, deny)
		if dmg {
			damaged = true
		}
		if err != nil {
			return header{}, damaged, fmt.Errorf("reading comments: %w", err)
		}
		builder.WriteByte(n[0])
	}
	comments := builder.String()

	flags := [flagsSize]byte{}
	seeds := seeds{}
	refs := refs{}
	loop := [][]byte{
		flags[:],
		seeds.salt[:], seeds.hkdfSalt[:], seeds.serpentIV[:], seeds.nonce[:],
		refs.keyRef[:], refs.keyfileRef[:], refs.macTag[:],
	}
	for _, s := range loop {
		h, dmg, err := readFromHeader(reader, len(s), deny)
		if dmg {
			damaged = true
		}
		if err != nil {
			return header{}, false, fmt.Errorf("reading header fields: %w", err)
		}
		copy(s, h)
	}
	if deny != nil {
		seeds.denyNonce = deny.nonce
		seeds.denySalt = deny.salt
	}
	settings := Settings{
		Comments:    comments,
		ReedSolomon: flags[3] == 1,
		Paranoid:    flags[0] == 1,
		OrderedKf:   flags[2] == 1,
		Deniability: deny != nil,
	}

	return header{
		settings: settings,
		seeds:    seeds,
		refs:     refs,
		usesKf:   flags[1] == 1,
	}, false, nil
}
