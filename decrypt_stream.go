package picocryption

import (
	"bytes"
	"crypto/hmac"
	"errors"
	"hash"
	"io"
	"log"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type macStream struct {
	mac        hash.Hash
	encrypting bool
	header     *header
}

func (ms *macStream) stream(p []byte) ([]byte, error) {
	_, err := ms.mac.Write(p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

func (ms *macStream) flush() ([]byte, error) {
	m := ms.mac.Sum(nil)
	if ms.encrypting {
		log.Println("Saving mac tag")
		copy(ms.header.refs.macTag[:], m)
		return nil, nil
	}
	log.Println("Comparing mac tag")
	if !hmac.Equal(m, ms.header.refs.macTag[:]) {
		log.Println("Comparison failed")
		return nil, ErrBodyCorrupted
	}
	log.Println("Comparison passed:", m)
	return nil, nil
}

func newMacStream(keys keys, header *header, encrypting bool) (*macStream, error) {
	var mac hash.Hash
	if header.settings.Paranoid {
		mac = hmac.New(sha3.New512, keys.macKey[:])
	} else {
		var err error
		mac, err = blake2b.New512(keys.macKey[:])
		if err != nil {
			return nil, err
		}
	}
	return &macStream{mac: mac, header: header, encrypting: encrypting}, nil
}

type decryptStream struct {
	password      string
	keyfiles      []io.Reader
	headerStream  *headerStream
	bodyStreams   []streamerFlusher
	damageTracker *damageTracker
}

func (ds *decryptStream) stream(p []byte) ([]byte, error) {
	p, err := ds.headerStream.stream(p)
	if err != nil {
		return nil, err
	}
	if ds.headerStream.isDone() {
		if ds.bodyStreams == nil {
			ds.bodyStreams, err = ds.makeBodyStreams()
			if err != nil {
				return nil, err
			}
		}
		return streamStack(ds.bodyStreams, p)
	}
	return p, nil
}

func (ds *decryptStream) flush() ([]byte, error) {
	if ds.bodyStreams == nil {
		return nil, nil
	}
	return flushStack(ds.bodyStreams)
}

func (ds *decryptStream) makeBodyStreams() ([]streamerFlusher, error) {
	// TODO implement keyfiles
	keys, err := validateKeys(ds.headerStream.header, ds.password, ds.keyfiles)
	if err != nil {
		// TODO should I include duplicate keyfiles error here?
		return nil, err
	}
	// TODO verify that the keyRef matches the header
	streams := []streamerFlusher{}
	// TODO: add reed solomon if configured
	if ds.headerStream.header.settings.ReedSolomon {
		streams = append(streams, makeRSDecodeStream(false, ds.damageTracker))
	}
	macStream, err := newMacStream(keys, ds.headerStream.header, false)
	if err != nil {
		return nil, err
	}
	streams = append(streams, macStream)
	encryptionStreams, err := newEncryptionStreams(keys, ds.headerStream.header)
	if err != nil {
		return nil, err
	}
	streams = append(streams, encryptionStreams...)
	return streams, nil
}

func makeDecryptStream(password string, keyfiles []io.Reader, damageTracker *damageTracker) *decryptStream {
	header := header{}
	return &decryptStream{
		password:      password,
		keyfiles:      keyfiles,
		headerStream:  makeHeaderStream(password, &header, damageTracker),
		damageTracker: damageTracker,
	}
}

func validateKeys(header *header, password string, keyfiles []io.Reader) (keys, error) {
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
