package picocryption

import (
	"crypto/hmac"
	"hash"
	"log"

	"github.com/Picocrypt/serpent"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/sha3"
)

type macStream struct {
	mac        hash.Hash
	encrypting bool
	header     *header
}

func (ms *macStream) stream(p []byte) ([]byte, bool, error) {
	log.Println("Writing to mac stream:", len(p))
	_, err := ms.mac.Write(p)
	if err != nil {
		return nil, false, err
	}
	return p, false, nil
}

func (ms *macStream) flush() ([]byte, bool, error) {
	log.Println("Flushing mac stream")
	m := ms.mac.Sum(nil)
	if ms.encrypting {
		log.Println("Saving mac tag")
		copy(ms.header.refs.macTag[:], m)
		return nil, false, nil
	}
	log.Println("Comparing mac tag")
	if !hmac.Equal(m, ms.header.refs.macTag[:]) {
		log.Println("Comparison failed")
		return nil, true, ErrCorrupted
	}
	log.Println("Comparison passed:", m)
	return nil, false, nil
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
	headerStream
	bodyStream streamer
}

func (ds *decryptStream) stream(p []byte) ([]byte, bool, error) {
	log.Println("Len before header stream: ", len(p))
	p, damaged, err := ds.headerStream.stream(p)
	log.Println("Len after header stream: ", len(p))
	if err != nil {
		return nil, damaged, err
	}
	if ds.headerStream.isDone() {
		if ds.bodyStream == nil {
			ds.bodyStream, err = ds.makeBodyStream()
			if err != nil {
				return nil, damaged, err
			}
		}
		return ds.bodyStream.stream(p)
	}
	return p, damaged, nil
}

func (ds *decryptStream) flush() ([]byte, bool, error) {
	if ds.bodyStream == nil {
		return nil, false, nil
	}
	return ds.bodyStream.flush()
}

func (ds *decryptStream) makeBodyStream() (streamer, error) {
	// TODO implement keyfiles
	log.Println("Expected mac:", ds.header.refs.macTag)
	keys, err := newKeys(ds.header.settings, ds.header.seeds, ds.password, nil)
	if err != nil {
		// TODO should I include duplicate keyfiles error here?
		return nil, err
	}
	// TODO verify that the keyRef matches the header
	nonceManager := newNonceManager(keys)
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
	streams = append(streams,
		&rotatingCipher{
			xorCipher: &chachaCipher{
				nonceManager: nonceManager,
				key:          keys.key[:],
			},
		},
	)
	if ds.header.settings.Paranoid {
		sb, err := serpent.NewCipher(keys.serpentKey[:])
		if err != nil {
			return nil, err
		}
		streams = append(streams, &rotatingCipher{
			xorCipher: &serpentCipher{
				serpentBlock: sb,
				nonceManager: nonceManager,
				header:       ds.header,
			},
		})
	}
	return &stackedStream{streams: streams}, nil
}

func makeDecryptStream(password string) *decryptStream {
	header := header{}
	return &decryptStream{
		password:     password,
		headerStream: makeHeaderStream(password, &header),
	}
}
