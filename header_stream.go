package picocryption

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type streamer interface {
	stream(p []byte) ([]byte, bool, error)
	flush() ([]byte, bool, error)
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
	buff buffer
}

func (v *versionReader) stream(p []byte) ([]byte, bool, error) {
	damaged := false
	if !v.buff.isFull() {
		p = v.buff.add(p)
		if v.buff.isFull() {
			// check that the version is actually good
			version := make([]byte, versionSize)
			var err error
			damaged, err = rsDecode(version, v.buff.data, false)
			if err != nil {
				return nil, damaged, fmt.Errorf("decoding version: %w", err)
			}
			valid, err := regexp.Match(`^v1\.\d{2}`, []byte(version))
			if err != nil {
				return nil, damaged, fmt.Errorf("parsing version format: %w", err)
			}
			if !valid {
				return nil, true, ErrCorrupted
			}
		}
	}
	return p, damaged, nil
}

func (v *versionReader) flush() ([]byte, bool, error) {
	return nil, false, nil
}

func makeVersionReader() versionReader {
	return versionReader{
		buff: buffer{size: versionSize * 3},
	}
}

type deniabilityReader struct {
	password string
	buff     buffer
	deny     *deniability
	header   *header
}

func (d *deniabilityReader) stream(p []byte) ([]byte, bool, error) {
	if !d.buff.isFull() {
		p = d.buff.add(p)
		if d.buff.isFull() {
			// if the opening data is a valid version, then the deniability
			// reader doesn't need to do anything. If the opening data is not
			// a valid version, then the deniability reader needs to activate.
			vr := makeVersionReader()
			_, _, err := vr.stream(d.buff.data)
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
					return nil, false, fmt.Errorf("creating deniability cipher: %w", err)
				}
			}
		}
	}
	if d.deny != nil {
		err := d.deny.deny(p)
		if err != nil {
			return nil, false, fmt.Errorf("denying data: %w", err)
		}
	}
	return p, false, nil
}

func (d *deniabilityReader) flush() ([]byte, bool, error) {
	return nil, false, nil
}

func makeDeniabilityReader(password string, header *header) deniabilityReader {
	return deniabilityReader{
		password: password,
		buff:     buffer{size: 16 + 24}, // 16 bytes for salt, 24 bytes for nonce
		header:   header,
	}
}

type flagStream struct {
	buff   buffer
	header *header
}

func (f *flagStream) stream(p []byte) ([]byte, bool, error) {
	if !f.buff.isFull() {
		p = f.buff.add(p)
		if f.buff.isFull() {
			data := make([]byte, flagsSize)
			damaged, err := rsDecode(data, f.buff.data, false)
			if err != nil {
				return nil, damaged, fmt.Errorf("decoding flags: %w", err)
			}
			f.header.settings.Paranoid = data[0] == 1
			f.header.usesKf = data[1] == 1
			f.header.settings.OrderedKf = data[2] == 1
			f.header.settings.ReedSolomon = data[3] == 1
		}
	}
	return p, false, nil
}

func (f *flagStream) flush() ([]byte, bool, error) {
	return nil, false, nil
}

func makeFlagStream(header *header) flagStream {
	return flagStream{
		buff:   buffer{size: flagsSize * 3},
		header: header,
	}
}

type commentStream struct {
	lenBuff     buffer
	commentBuff buffer
	header      *header
}

func (c *commentStream) stream(p []byte) ([]byte, bool, error) {
	if !c.lenBuff.isFull() {
		p = c.lenBuff.add(p)
		if c.lenBuff.isFull() {
			cLenRune := make([]byte, commentSize)
			damaged, err := rsDecode(cLenRune, c.lenBuff.data, false)
			if err != nil {
				return nil, damaged, fmt.Errorf("decoding comment length: %w", err)
			}
			cLen, err := strconv.Atoi(string(cLenRune))
			if err != nil {
				return nil, false, fmt.Errorf("parsing comment length: %w", ErrCorrupted)
			}
			c.commentBuff = buffer{size: cLen * 3}
		}
	}
	if c.lenBuff.isFull() && !c.commentBuff.isFull() {
		p = c.commentBuff.add(p)
		if c.commentBuff.isFull() {
			var builder strings.Builder
			damaged := false
			for i := 0; i < len(c.commentBuff.data); i += 3 {
				value := [1]byte{}
				dmg, err := rsDecode(value[:], c.commentBuff.data[i:i+3], false)
				if dmg {
					damaged = true
				}
				if err != nil {
					return nil, damaged, fmt.Errorf("decoding comment length: %w", err)
				}
				builder.WriteByte(value[0])
			}
			c.header.settings.Comments = builder.String()
		}
	}
	return p, false, nil
}

func (c *commentStream) flush() ([]byte, bool, error) {
	return nil, false, nil
}

func makeCommentStream(header *header) commentStream {
	return commentStream{
		lenBuff: buffer{size: commentSize * 3},
		header:  header,
	}
}

type sliceStream struct {
	buff  buffer
	slice []byte
}

func (s *sliceStream) stream(p []byte) ([]byte, bool, error) {
	damaged := false
	if !s.buff.isFull() {
		p = s.buff.add(p)
		if s.buff.isFull() {
			data := make([]byte, len(s.slice))
			var err error
			damaged, err = rsDecode(data, s.buff.data, false)
			if err != nil {
				return nil, damaged, fmt.Errorf("decoding slice: %w", err)
			}
			copy(s.slice, data)
		}
	}
	return p, damaged, nil
}

func (s *sliceStream) flush() ([]byte, bool, error) {
	return nil, false, nil
}

func makeSliceStream(slice []byte) sliceStream {
	return sliceStream{
		buff:  buffer{size: len(slice) * 3},
		slice: slice,
	}
}

type stackedStream struct {
	streams []streamer
}

func (s *stackedStream) stream(p []byte) ([]byte, bool, error) {
	damaged := false
	for _, stream := range s.streams {
		var err error
		var dmg bool
		p, dmg, err = stream.stream(p)
		damaged = damaged || dmg
		if err != nil {
			return nil, damaged, err
		}
		if len(p) == 0 {
			break
		}
	}
	return p, damaged, nil
}

func (s *stackedStream) flush() ([]byte, bool, error) {
	damaged := false
	p := []byte{}
	for _, stream := range s.streams {
		pStream, dmg, err := stream.stream(p)
		damaged = damaged || dmg
		if err != nil {
			return nil, damaged, err
		}
		pFlush, dmg, err := stream.flush()
		damaged = damaged || dmg
		if err != nil {
			return nil, damaged, err
		}
		p = append(pStream, pFlush...)
	}
	return p, damaged, nil
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

func (h *headerStream) stream(p []byte) ([]byte, bool, error) {
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

func makeHeaderStream(password string, header *header) headerStream {
	return headerStream{
		header,
		makeDeniabilityReader(password, header),
		makeVersionReader(),
		makeCommentStream(header),
		makeFlagStream(header),
		makeSliceStream(header.seeds.salt[:]),
		makeSliceStream(header.seeds.hkdfSalt[:]),
		makeSliceStream(header.seeds.serpentIV[:]),
		makeSliceStream(header.seeds.nonce[:]),
		makeSliceStream(header.refs.keyRef[:]),
		makeSliceStream(header.refs.keyfileRef[:]),
		makeSliceStream(header.refs.macTag[:]),
	}
}
