package picocryption

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type damageTracker struct {
	damage bool
}

type streamer interface {
	stream(p []byte) ([]byte, error)
	flush() ([]byte, error)
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

type versionReader struct {
	buff          buffer
	damageTracker *damageTracker
}

func (v *versionReader) stream(p []byte) ([]byte, error) {
	if !v.buff.isFull() {
		p = v.buff.add(p)
		if v.buff.isFull() {
			// check that the version is actually good
			version := make([]byte, versionSize)
			damaged, _, err := rsDecode(version, v.buff.data, false)
			v.damageTracker.damage = v.damageTracker.damage || damaged
			if err != nil {
				return nil, fmt.Errorf("decoding version: %w", err)
			}
			valid, err := regexp.Match(`^v1\.\d{2}`, []byte(version))
			if err != nil {
				return nil, fmt.Errorf("parsing version format: %w", err)
			}
			if !valid {
				return nil, ErrHeaderCorrupted
			}
		}
	}
	return p, nil
}

func (v *versionReader) flush() ([]byte, error) {
	return nil, nil
}

func makeVersionReader(damageTracker *damageTracker) versionReader {
	return versionReader{
		buff:          buffer{size: versionSize * 3},
		damageTracker: damageTracker,
	}
}

type deniabilityReader struct {
	password string
	buff     buffer
	deny     *deniability
	header   *header
}

func (d *deniabilityReader) stream(p []byte) ([]byte, error) {
	if !d.buff.isFull() {
		p = d.buff.add(p)
		if d.buff.isFull() {
			// if the opening data is a valid version, then the deniability
			// reader doesn't need to do anything. If the opening data is not
			// a valid version, then the deniability reader needs to activate.
			vr := makeVersionReader(&damageTracker{})
			_, err := vr.stream(d.buff.data)
			if err == nil {
				d.header.settings.Deniability = false
				p = append(d.buff.data, p...)
			} else {
				d.header.settings.Deniability = true
				salt := [16]byte{}
				nonce := [24]byte{}
				copy(salt[:], d.buff.data[:len(salt)])
				copy(nonce[:], d.buff.data[len(salt):])
				key := generateDenyKey(d.password, salt)
				d.deny, err = newDeniability(key, nonce, salt, 0)
				if err != nil {
					return nil, fmt.Errorf("creating deniability cipher: %w", err)
				}
			}
		}
	}
	if d.deny != nil {
		err := d.deny.deny(p)
		if err != nil {
			return nil, fmt.Errorf("denying data: %w", err)
		}
	}
	return p, nil
}

func (d *deniabilityReader) flush() ([]byte, error) {
	return nil, nil
}

func makeDeniabilityReader(password string, header *header) deniabilityReader {
	return deniabilityReader{
		password: password,
		buff:     buffer{size: 16 + 24}, // 16 bytes for salt, 24 bytes for nonce
		header:   header,
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

func (f *flagStream) flush() ([]byte, error) {
	return nil, nil
}

func makeFlagStream(header *header, damageTracker *damageTracker) flagStream {
	return flagStream{
		buff:          buffer{size: flagsSize * 3},
		header:        header,
		damageTracker: damageTracker,
	}
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

func (c *commentStream) flush() ([]byte, error) {
	return nil, nil
}

func makeCommentStream(header *header, damageTracker *damageTracker) commentStream {
	return commentStream{
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

func (s *sliceStream) flush() ([]byte, error) {
	return nil, nil
}

func makeSliceStream(slice []byte, damagedTracker *damageTracker) sliceStream {
	return sliceStream{
		buff:          buffer{size: len(slice) * 3},
		slice:         slice,
		damageTracker: damagedTracker,
	}
}

type stackedStream struct {
	streams []streamer
}

func (s *stackedStream) stream(p []byte) ([]byte, error) {
	for _, stream := range s.streams {
		p, err := stream.stream(p)
		if err != nil {
			return nil, err
		}
		if len(p) == 0 {
			break
		}
	}
	return p, nil
}

func (s *stackedStream) flush() ([]byte, error) {
	p := []byte{}
	for _, stream := range s.streams {
		pStream, err := stream.stream(p)
		if err != nil {
			return nil, err
		}
		pFlush, err := stream.flush()
		if err != nil {
			return nil, err
		}
		p = append(pStream, pFlush...)
	}
	return p, nil
}

type headerStream struct {
	header *header
	deniabilityReader
	versionReader
	commentStream
	flagStream
	saltStream       sliceStream
	hkdfSaltStream   sliceStream
	serpentIVStream  sliceStream
	nonceStream      sliceStream
	keyRefStream     sliceStream
	keyfileRefStream sliceStream
	macTagStream     sliceStream
}

func (h *headerStream) stream(p []byte) ([]byte, error) {
	stack := stackedStream{
		streams: []streamer{
			&h.deniabilityReader,
			&h.versionReader,
			&h.commentStream,
			&h.flagStream,
			&h.saltStream,
			&h.hkdfSaltStream,
			&h.serpentIVStream,
			&h.nonceStream,
			&h.keyRefStream,
			&h.keyfileRefStream,
			&h.macTagStream,
		},
	}
	return stack.stream(p)
}

func (h *headerStream) isDone() bool {
	return h.macTagStream.buff.isFull()
}

func makeHeaderStream(password string, header *header, damageTracker *damageTracker) headerStream {
	return headerStream{
		header,
		makeDeniabilityReader(password, header),
		makeVersionReader(damageTracker),
		makeCommentStream(header, damageTracker),
		makeFlagStream(header, damageTracker),
		makeSliceStream(header.seeds.salt[:], damageTracker),
		makeSliceStream(header.seeds.hkdfSalt[:], damageTracker),
		makeSliceStream(header.seeds.serpentIV[:], damageTracker),
		makeSliceStream(header.seeds.nonce[:], damageTracker),
		makeSliceStream(header.refs.keyRef[:], damageTracker),
		makeSliceStream(header.refs.keyfileRef[:], damageTracker),
		makeSliceStream(header.refs.macTag[:], damageTracker),
	}
}
