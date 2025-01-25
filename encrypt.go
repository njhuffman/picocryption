package picocryption

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

var picocryptVersion = "v1.43"

type encryptor struct {
	writer   io.Writer
	mac      hash.Hash
	ec       *encryptionCipher
	deny     *deniability
	rs       *rsBodyEncoder
	comments string
	written  int
	closed   bool
}

func (w *encryptor) write(p []byte) error {

	data := make([]byte, len(p))
	err := w.ec.encode(data, p)
	if err != nil {
		return fmt.Errorf("encrypting stream: %w", err)
	}
	w.mac.Write(data)
	w.written += len(data)
	if w.rs != nil {
		data = w.rs.encode(data)
	}
	if w.deny != nil {
		err := w.deny.deny(data)
		if err != nil {
			return err
		}
	}
	_, err = w.writer.Write(data)
	if err != nil {
		return fmt.Errorf("writing encrypted data: %w", err)
	}
	return nil
}

func (w *encryptor) close() error {
	w.closed = true
	if w.rs == nil {
		return nil
	}
	data := w.rs.flush()
	if w.deny != nil {
		err := w.deny.deny(data)
		if err != nil {
			return err
		}
	}
	_, err := w.writer.Write(data)
	return err
}

func (w *encryptor) makeHeader() ([]byte, error) {
	data := [][]byte{[]byte(picocryptVersion)}
	data = append(data, []byte(fmt.Sprintf("%05d", len(w.comments))))
	for _, c := range []byte(w.comments) {
		data = append(data, []byte{c})
	}
	flags := []bool{
		w.ec.keys.settings.Paranoid,
		w.ec.keys.usesKeyfiles,
		w.ec.keys.settings.OrderedKf,
		w.rs != nil,
		w.written%(1<<20) > (1<<20)-chunkSize,
	}
	flagBytes := make([]byte, len(flags))
	for i, f := range flags {
		if f {
			flagBytes[i] = 1
		}
	}
	data = append(data, flagBytes)
	data = append(data, w.ec.keys.seeds.salt[:])
	data = append(data, w.ec.keys.seeds.hkdfSalt[:])
	data = append(data, w.ec.keys.seeds.serpentIV[:])
	data = append(data, w.ec.keys.seeds.nonce[:])
	data = append(data, w.ec.keys.keyRef[:])
	data = append(data, w.ec.keys.keyfileRef[:])
	data = append(data, w.mac.Sum(nil))

	header := make([]byte, baseHeaderSize+len(w.comments)*3)
	written := 0
	for _, d := range data {
		err := rsEncode(header[written:written+len(d)*3], d)
		if err != nil {
			return nil, err
		}
		written += len(d) * 3
	}

	if w.deny != nil {
		deny, err := newDeniability(w.ec.keys.denyKey, w.ec.keys.seeds.denyNonce, w.ec.keys.seeds.denySalt, 0)
		if err != nil {
			return nil, fmt.Errorf("creating deniability cipher: %w", err)
		}
		deny.deny(header)
		header = bytes.Join([][]byte{deny.salt[:], deny.nonce[:], header}, nil)
	}

	return header, nil
}

func newEncryptor(w io.Writer, settings Settings, seeds seeds, password string, keyfiles []io.Reader) (*encryptor, error) {

	keys, err := newKeys(settings, seeds, password, keyfiles)
	if err != nil {
		return nil, err
	}

	var mac hash.Hash
	if settings.Paranoid {
		mac = hmac.New(sha3.New512, keys.macKey[:])
	} else {
		var err error
		mac, err = blake2b.New512(keys.macKey[:])
		if err != nil {
			return nil, fmt.Errorf("creating blake2b: %w", err)
		}
	}

	ec, err := newEncryptionCipher(keys)
	if err != nil {
		return nil, fmt.Errorf("creating encryption cipher: %w", err)
	}

	var deny *deniability
	if settings.Deniability {
		offset := baseHeaderSize + 3*len(settings.Comments)
		deny, err = newDeniability(keys.denyKey, seeds.denyNonce, seeds.denySalt, offset)
		if err != nil {
			return nil, fmt.Errorf("creating deniability cipher: %w", err)
		}
	}

	var rs *rsBodyEncoder
	if settings.ReedSolomon {
		rs = &rsBodyEncoder{}
	}

	return &encryptor{w, mac, ec, deny, rs, settings.Comments, 0, false}, nil
}
