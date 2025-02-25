package picocryption

import (
	"fmt"
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

	streams := []streamer{}

	encryptionStream, err := newEncryptionStream(keys, &header)
	if err != nil {
		return nil, fmt.Errorf("creating encryption stream: %w", err)
	}
	streams = append(streams, encryptionStream)

	macStream, err := newMacStream(keys, &header, true)
	if err != nil {
		return nil, fmt.Errorf("creating mac stream: %w", err)
	}
	streams = append(streams, macStream)

	if settings.ReedSolomon {
		streams = append(streams, makeRSEncodeStream())
	}

	if settings.Deniability {
		deniabilityStream := newDeniabilityStream(password, &header)
		mockHeaderData := make([]byte, baseHeaderSize+3*len(settings.Comments))
		_, _, err := deniabilityStream.stream(mockHeaderData)
		if err != nil {
			return nil, fmt.Errorf("seeding deniability stream: %w", err)
		}
		streams = append(streams, deniabilityStream)
	}

	return &encryptStream{
		header:  &header,
		streams: stackedStream{streams: streams},
	}, nil
}
