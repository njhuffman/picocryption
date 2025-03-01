package picocryption

import (
	"crypto/hmac"
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
	password string
	keyfiles []io.Reader
	headerStream
	bodyStream streamer
}

func (ds *decryptStream) stream(p []byte) ([]byte, error) {
	p, err := ds.headerStream.stream(p)
	if err != nil {
		return nil, err
	}
	if ds.headerStream.isDone() {
		if ds.bodyStream == nil {
			ds.bodyStream, err = ds.makeBodyStream()
			if err != nil {
				return nil, err
			}
		}
		return ds.bodyStream.stream(p)
	}
	return p, nil
}

func (ds *decryptStream) flush() ([]byte, error) {
	if ds.bodyStream == nil {
		return nil, nil
	}
	return ds.bodyStream.flush()
}

func (ds *decryptStream) makeBodyStream() (streamer, error) {
	// TODO implement keyfiles
	keys, err := newKeys(ds.header.settings, ds.header.seeds, ds.password, ds.keyfiles)
	if err != nil {
		// TODO should I include duplicate keyfiles error here?
		return nil, err
	}
	// TODO verify that the keyRef matches the header
	streams := []streamer{}
	// TODO: add reed solomon if configured
	if ds.header.settings.ReedSolomon {
		streams = append(streams, makeRSDecodeStream(false))
	}
	macStream, err := newMacStream(keys, ds.header, false)
	if err != nil {
		return nil, err
	}
	streams = append(streams, macStream)
	encryptionStream, err := newEncryptionStream(keys, ds.header)
	if err != nil {
		return nil, err
	}
	streams = append(streams, encryptionStream)
	return &stackedStream{streams: streams}, nil
}

func makeDecryptStream(password string, keyfiles []io.Reader, damageTracker *damageTracker) *decryptStream {
	header := header{}
	return &decryptStream{
		password:     password,
		keyfiles:     keyfiles,
		headerStream: makeHeaderStream(password, &header, damageTracker),
	}
}
