package picocryption

import (
	"fmt"

	"github.com/Picocrypt/serpent"
)

type encryptStream struct {
	header  *header
	streams stackedStream
}

func (es *encryptStream) stream(p []byte) ([]byte, bool, error) {
	return es.streams.stream(p)
}

func (es *encryptStream) flush() ([]byte, bool, error) {
	return es.streams.flush()
}

func makeEncryptStream(settings Settings, seeds seeds, password string) (*encryptStream, error) {
	header := header{}
	header.settings = settings
	header.seeds = seeds
	keys, err := newKeys(settings, seeds, password, nil)
	if err != nil {
		return nil, fmt.Errorf("generating keys: %w", err)
	}
	nonceManager := newNonceManager(keys)
	streams := []streamer{}
	if header.settings.Paranoid {
		sb, err := serpent.NewCipher(keys.serpentKey[:])
		if err != nil {
			return nil, fmt.Errorf("creating serpent cipher: %w", err)
		}
		streams = append(streams, &rotatingCipher{
			xorCipher: &serpentCipher{
				serpentBlock: sb,
				nonceManager: nonceManager,
				header:       &header,
			},
		})
	}
	streams = append(streams, &rotatingCipher{
		xorCipher: &chachaCipher{
			nonceManager: nonceManager,
			key:          keys.key[:],
		},
	})
	macStream, err := newMacStream(keys, &header, true)
	if err != nil {
		return nil, fmt.Errorf("creating mac stream: %w", err)
	}
	streams = append(streams, macStream)
	// TODO: add reed solomon if configured
	if settings.ReedSolomon {
		streams = append(streams, makeRSEncodeStream())
	}
	// TODO: add deniability if configured
	return &encryptStream{
		header:  &header,
		streams: stackedStream{streams: streams},
	}, nil
}
