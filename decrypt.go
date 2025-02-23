package picocryption

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type refs struct {
	keyRef     [64]byte
	keyfileRef [32]byte
	macTag     [64]byte
}

type decryptor struct {
	reader    io.Reader
	mac       hash.Hash
	ec        *encryptionCipher
	deny      *deniability
	rs        *rsBodyDecoder
	macTag    [64]byte
	rEof      bool
	rsFlushed bool
	buffer    []byte
	done      bool
}

func (d *decryptor) read(p []byte) (int, bool, error) {
	if d.done {
		return 0, false, io.EOF
	}

	data := []byte{}
	if !d.rEof {
		data = make([]byte, max(len(p)-len(d.buffer), 0))
		n, err := d.reader.Read(data)
		data = data[:n]
		if errors.Is(err, io.EOF) {
			d.rEof = true
		} else if err != nil {
			return 0, false, err
		}
	}

	if d.deny != nil && len(data) > 0 {
		err := d.deny.deny(data)
		if err != nil {
			return 0, false, err
		}
	}

	var decodeErr error
	damaged := false
	if d.rs != nil && len(data) > 0 {
		data, damaged, decodeErr = d.rs.decode(data)
	} else if d.rEof && !d.rsFlushed && d.rs != nil {
		d.rsFlushed = true
		var flushData []byte
		flushData, damaged, decodeErr = d.rs.flush()
		data = append(data, flushData...)
	}

	d.mac.Write(data)
	err := d.ec.encode(data, data)
	if err != nil {
		return 0, damaged, fmt.Errorf("encrypting stream: %w", err)
	}
	d.buffer = append(d.buffer, data...)

	n := copy(p, d.buffer)
	d.buffer = d.buffer[n:]
	if (len(d.buffer) == 0) && d.rEof {
		d.done = true
		macTag := d.mac.Sum(nil)
		if !bytes.Equal(macTag, d.macTag[:]) {
			decodeErr = ErrCorrupted
		}
		if decodeErr == nil {
			decodeErr = io.EOF
		}
	}
	return n, damaged, decodeErr
}

func validateKeys(header header, password string, keyfiles []io.Reader) (keys, error) {
	if header.usesKf && len(keyfiles) == 0 {
		return keys{}, ErrKeyfilesRequired
	}
	if !header.usesKf && len(keyfiles) > 0 {
		return keys{}, ErrKeyfilesNotRequired
	}
	keys, err := newKeys(header.settings, header.seeds, password, keyfiles)
	if err != nil && !errors.Is(err, ErrDuplicateKeyfiles) {
		return keys, err
	}
	if !bytes.Equal(keys.keyRef[:], header.refs.keyRef[:]) {
		return keys, ErrIncorrectPassword
	}
	if header.usesKf && !bytes.Equal(keys.keyfileRef[:], header.refs.keyfileRef[:]) {
		if header.settings.OrderedKf {
			return keys, ErrIncorrectOrMisorderedKeyfiles
		}
		return keys, ErrIncorrectKeyfiles
	}
	return keys, nil
}

func createMAC(keys keys, settings Settings) (hash.Hash, error) {
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
	return mac, nil
}

func newDecryptor(
	password string,
	keyfiles []io.Reader,
	reader io.Reader,
	skipReedSolomon bool,
	update chan Update,
) (*decryptor, bool, error) {
	if update != nil {
		update <- Update{"Parsing Header", 0, 0}
	}
	header, damaged, err := readHeader(reader, password)
	if err != nil {
		return nil, damaged, err
	}

	if update != nil {
		update <- Update{"Generating keys", 0, 0}
	}
	keys, err := validateKeys(header, password, keyfiles)
	if err != nil {
		return nil, damaged, err
	}

	var rs *rsBodyDecoder
	if header.settings.ReedSolomon {
		rs = &rsBodyDecoder{[]byte{}, skipReedSolomon}
	}

	mac, err := createMAC(keys, header.settings)
	if err != nil {
		return nil, damaged, fmt.Errorf("creating mac: %w", err)
	}

	ec, err := newEncryptionCipher(keys)
	if err != nil {
		return nil, damaged, fmt.Errorf("creating encryption cipher: %w", err)
	}

	var deny *deniability
	if header.settings.Deniability {
		offset := header.size() - len(header.seeds.denyNonce) - len(header.seeds.denySalt)
		deny, err = newDeniability(generateDenyKey(password, header.seeds.denySalt), header.seeds.denyNonce, header.seeds.denySalt, offset)
		if err != nil {
			return nil, damaged, fmt.Errorf("creating deniability cipher: %w", err)
		}
	}

	decryptor := &decryptor{
		reader: reader,
		mac:    mac,
		ec:     ec,
		deny:   deny,
		rs:     rs,
		macTag: header.refs.macTag,
	}
	return decryptor, damaged, nil
}
