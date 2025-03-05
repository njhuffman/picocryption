package picocryption

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type damageTracker struct {
	damage bool
}

type buffer struct {
	size int
	data []byte
}

func (b *buffer) isFull() bool {
	return len(b.data) == b.size
}

func (b *buffer) add(p []byte) []byte {
	idx := len(p)
	if len(p) > b.size-len(b.data) {
		idx = b.size - len(b.data)
	}
	if idx > 0 {
		b.data = append(b.data, p[:idx]...)
		return p[idx:]
	}
	return p
}

func parseVersion(versionBytes []byte) (bool, string, error) {
	if len(versionBytes) != (versionSize * 3) {
		return false, "", fmt.Errorf("invalid version length: %d", len(versionBytes))
	}
	v := make([]byte, versionSize)
	damaged, _, err := rsDecode(v, versionBytes[:], false)
	if err != nil {
		return damaged, "", fmt.Errorf("decoding version: %w", err)
	}
	valid, err := regexp.Match(`^v1\.\d{2}`, v)
	if err != nil {
		return damaged, "", fmt.Errorf("parsing version format: %w", err)
	}
	if !valid {
		return damaged, "", nil
	}
	return damaged, string(v), nil
}

type versionStream struct {
	buff          buffer
	damageTracker *damageTracker
}

func (v *versionStream) stream(p []byte) ([]byte, error) {
	if !v.buff.isFull() {
		p = v.buff.add(p)
		if v.buff.isFull() {
			// check that the version is actually good
			damaged, version, err := parseVersion(v.buff.data)
			v.damageTracker.damage = v.damageTracker.damage || damaged
			if err != nil {
				return nil, fmt.Errorf("parsing version: %w", err)
			}
			if version == "" {
				return nil, ErrHeaderCorrupted
			}
		}
	}
	return p, nil
}

func makeVersionStream(damageTracker *damageTracker) *versionStream {
	return &versionStream{
		buff:          buffer{size: versionSize * 3},
		damageTracker: damageTracker,
	}
}

type deniabilityStream struct {
	password string
	buff     buffer
	deny     streamer
	header   *header
}

func (d *deniabilityStream) stream(p []byte) ([]byte, error) {
	if !d.buff.isFull() {
		p = d.buff.add(p)
		if d.buff.isFull() {
			// Don't catch damaged flag, it is handled by the version stream
			_, version, err := parseVersion(d.buff.data[:versionSize*3])
			if err != nil {
				return nil, fmt.Errorf("parsing version: %w", err)
			}
			if version != "" {
				d.header.settings.Deniability = false
				p = append(d.buff.data, p...)
			} else {
				d.header.settings.Deniability = true
				salt := [16]byte{}
				nonce := [24]byte{}
				copy(salt[:], d.buff.data[:len(salt)])
				copy(nonce[:], d.buff.data[len(salt):])
				d.header.seeds.DenyNonce = nonce
				d.header.seeds.DenySalt = salt
				d.deny = newDeniabilityStream(d.password, d.header)
			}
		}
	}
	if d.deny != nil {
		var err error
		p, err = d.deny.stream(p)
		if err != nil {
			return nil, fmt.Errorf("denying data: %w", err)
		}
	}
	return p, nil
}

func makeHeaderDeniabilityStream(password string, header *header) *deniabilityStream {
	return &deniabilityStream{
		password: password,
		buff:     buffer{size: 16 + 24}, // 16 bytes for salt, 24 bytes for nonce
		header:   header,
		deny:     nil, // will be set during streaming
	}
}

type flagStream struct {
	buff          buffer
	header        *header
	damageTracker *damageTracker
}

func (f *flagStream) stream(p []byte) ([]byte, error) {
	if !f.buff.isFull() {
		p = f.buff.add(p)
		if f.buff.isFull() {
			data := make([]byte, flagsSize)
			damaged, corrupted, err := rsDecode(data, f.buff.data, false)
			f.damageTracker.damage = f.damageTracker.damage || damaged
			if corrupted {
				return nil, ErrHeaderCorrupted
			}
			if err != nil {
				return nil, fmt.Errorf("decoding flags: %w", err)
			}
			f.header.settings.Paranoid = data[0] == 1
			f.header.usesKf = data[1] == 1
			f.header.settings.OrderedKf = data[2] == 1
			f.header.settings.ReedSolomon = data[3] == 1
		}
	}
	return p, nil
}

func makeFlagStream(header *header, damageTracker *damageTracker) *flagStream {
	return &flagStream{buffer{size: flagsSize * 3}, header, damageTracker}
}

type commentStream struct {
	lenBuff       buffer
	commentBuff   buffer
	header        *header
	damageTracker *damageTracker
}

func (c *commentStream) stream(p []byte) ([]byte, error) {
	if !c.lenBuff.isFull() {
		p = c.lenBuff.add(p)
		if c.lenBuff.isFull() {
			cLenRune := make([]byte, commentSize)
			damaged, corrupted, err := rsDecode(cLenRune, c.lenBuff.data, false)
			c.damageTracker.damage = c.damageTracker.damage || damaged
			if corrupted {
				return nil, ErrHeaderCorrupted
			}
			if err != nil {
				return nil, fmt.Errorf("decoding comment length: %w", err)
			}
			cLen, err := strconv.Atoi(string(cLenRune))
			if err != nil {
				return nil, fmt.Errorf("parsing comment length: %w", ErrHeaderCorrupted)
			}
			if (cLen < 0) || (cLen > maxCommentsLength) {
				return nil, ErrHeaderCorrupted
			}
			c.commentBuff = buffer{size: cLen * 3}
		}
	}
	if c.lenBuff.isFull() && !c.commentBuff.isFull() {
		p = c.commentBuff.add(p)
		if c.commentBuff.isFull() {
			var builder strings.Builder
			for i := 0; i < len(c.commentBuff.data); i += 3 {
				value := [1]byte{}
				// Ignore corruption on comments, they are not critical
				damaged, _, err := rsDecode(value[:], c.commentBuff.data[i:i+3], false)
				c.damageTracker.damage = c.damageTracker.damage || damaged
				if err != nil {
					return nil, fmt.Errorf("decoding comment length: %w", err)
				}
				builder.WriteByte(value[0])
			}
			c.header.settings.Comments = builder.String()
		}
	}
	return p, nil
}

func makeCommentStream(header *header, damageTracker *damageTracker) *commentStream {
	return &commentStream{
		lenBuff:       buffer{size: commentSize * 3},
		header:        header,
		damageTracker: damageTracker,
	}
}

type sliceStream struct {
	buff          buffer
	slice         []byte
	damageTracker *damageTracker
}

func (s *sliceStream) stream(p []byte) ([]byte, error) {
	if !s.buff.isFull() {
		p = s.buff.add(p)
		if s.buff.isFull() {
			data := make([]byte, len(s.slice))
			damaged, corrupted, err := rsDecode(data, s.buff.data, false)
			s.damageTracker.damage = s.damageTracker.damage || damaged
			if corrupted {
				return nil, ErrHeaderCorrupted
			}
			if err != nil {
				return nil, fmt.Errorf("decoding slice: %w", err)
			}
			copy(s.slice, data)
		}
	}
	return p, nil
}

func makeSliceStream(slice []byte, damagedTracker *damageTracker) *sliceStream {
	return &sliceStream{buffer{size: len(slice) * 3}, slice, damagedTracker}
}

type headerStream struct {
	header  *header
	streams []streamer
	isDone  func() bool
}

func (h *headerStream) stream(p []byte) ([]byte, error) {
	return streamStack(h.streams, p)
}

func makeHeaderStream(password string, header *header, damageTracker *damageTracker) *headerStream {
	macTagStream := makeSliceStream(header.refs.macTag[:], damageTracker)
	isDone := func() bool {
		return macTagStream.buff.isFull()
	}
	streams := []streamer{
		makeHeaderDeniabilityStream(password, header),
		makeVersionStream(damageTracker),
		makeCommentStream(header, damageTracker),
		makeFlagStream(header, damageTracker),
		makeSliceStream(header.seeds.Salt[:], damageTracker),
		makeSliceStream(header.seeds.HkdfSalt[:], damageTracker),
		makeSliceStream(header.seeds.SerpentIV[:], damageTracker),
		makeSliceStream(header.seeds.Nonce[:], damageTracker),
		makeSliceStream(header.refs.keyRef[:], damageTracker),
		makeSliceStream(header.refs.keyfileRef[:], damageTracker),
		macTagStream,
	}
	return &headerStream{header, streams, isDone}
}

func getHeader(r io.Reader, password string) (header, error) {
	h := header{}
	stream := makeHeaderStream(password, &h, &damageTracker{})
	for {
		p := make([]byte, 1000) // big enough to get most headers in one read
		n, err := r.Read(p)
		eof := errors.Is(err, io.EOF)
		if err != nil && !eof {
			return header{}, fmt.Errorf("reading file: %w", err)
		}
		_, err = stream.stream(p[:n])
		if err != nil {
			return header{}, fmt.Errorf("reading header: %w", err)
		}
		if stream.isDone() {
			return h, nil
		}
		if eof {
			return header{}, ErrFileTooShort
		}
	}
}
