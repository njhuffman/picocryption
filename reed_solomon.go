package picocryption

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/Picocrypt/infectious"
)

const (
	chunkSize   = 128
	encodedSize = 136
)

var (
	fecs   = make(map[[2]int]*infectious.FEC)
	fecsMu sync.Mutex
)

func getFEC(encoded, decoded []byte) (*infectious.FEC, error) {
	size := [2]int{len(decoded), len(encoded)}

	fecsMu.Lock()
	defer fecsMu.Unlock()

	fec := fecs[size]
	if fec != nil {
		return fec, nil
	}

	fec, err := infectious.NewFEC(size[0], size[1])
	if err != nil {
		return fec, err
	}

	fecs[size] = fec
	return fec, nil
}

func rsEncode(dst, src []byte) error {
	fec, err := getFEC(dst, src)
	if err != nil {
		return fmt.Errorf("failed to get FEC: %w", err)
	}
	return fec.Encode(src, func(s infectious.Share) { dst[s.Number] = s.Data[0] })
}

func rsDecode(dst, src []byte, skip bool) (bool, error) {
	if skip {
		copy(dst, src[:len(dst)])
		return false, nil
	}

	// Encoding is much faster than decoding. Try re-encoding the original
	// bytes and if the result matches, there must have been no corruption.
	recoded := make([]byte, len(src))
	rsEncode(recoded, src[:len(dst)])
	if bytes.Equal(recoded, src) {
		copy(dst, src[:len(dst)])
		return false, nil
	}

	// Attempt to recover damaged data
	fec, err := getFEC(src, dst)
	if err != nil {
		return false, fmt.Errorf("failed to get FEC: %w", err)
	}
	tmp := make([]infectious.Share, fec.Total())
	for i := 0; i < fec.Total(); i++ {
		tmp[i].Number = i
		tmp[i].Data = []byte{src[i]}
	}
	res, err := fec.Decode(nil, tmp)
	if err == nil {
		copy(dst, res)
		return true, nil
	}

	// Fully corrupted - use a best guess
	copy(dst, src[:len(dst)])
	return true, ErrCorrupted
}

type rsBodyEncoder struct {
	buffer []byte
}

func (r *rsBodyEncoder) encode(data []byte) []byte {
	r.buffer = append(r.buffer, data...)
	nChunks := len(r.buffer) / chunkSize
	rsData := make([]byte, nChunks*encodedSize)
	for i := 0; i < nChunks; i++ {
		rsEncode(rsData[i*encodedSize:(i+1)*encodedSize], r.buffer[i*chunkSize:(i+1)*chunkSize])
	}
	r.buffer = r.buffer[nChunks*chunkSize:]
	return rsData
}

func (r *rsBodyEncoder) flush() []byte {
	padding := make([]byte, chunkSize-len(r.buffer))
	for i := range padding {
		padding[i] = byte(chunkSize - len(r.buffer))
	}
	dst := make([]byte, encodedSize)
	rsEncode(dst, append(r.buffer, padding...))
	return dst
}

type rsBodyDecoder struct {
	buffer []byte
	skip   bool
}

func (r *rsBodyDecoder) decode(data []byte) ([]byte, bool, error) {
	r.buffer = append(r.buffer, data...)
	nChunks := len(r.buffer) / encodedSize
	// The last chunk might be padded, so keep it in the buffer for Flush
	if ((len(r.buffer) % encodedSize) == 0) && (nChunks > 0) {
		nChunks -= 1
	}
	rsData := make([]byte, nChunks*chunkSize)
	var decodeErr error
	damaged := false
	for i := 0; i < nChunks; i++ {
		src := r.buffer[i*encodedSize : (i+1)*encodedSize]
		dst := rsData[i*chunkSize : (i+1)*chunkSize]
		dmg, err := rsDecode(dst, src, r.skip)
		if dmg {
			damaged = true
		}
		if err != nil {
			decodeErr = err
		}
	}
	r.buffer = r.buffer[nChunks*encodedSize:]
	return rsData, damaged, decodeErr
}

func (r *rsBodyDecoder) flush() ([]byte, bool, error) {
	res := make([]byte, chunkSize)
	damaged, err := rsDecode(res, r.buffer, r.skip)
	keep := chunkSize - int(res[chunkSize-1])
	if keep < chunkSize {
		return res[:keep], damaged, err
	}
	return res, damaged, ErrCorrupted
}
