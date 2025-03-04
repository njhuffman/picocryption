package picocryption

import (
	"fmt"
	"io"
)

var picocryptVersion = "v1.43"

type encryptStream struct {
	header  *header
	streams []streamerFlusher
}

func (es *encryptStream) stream(p []byte) ([]byte, error) {
	return streamStack(es.streams, p)
}

func (es *encryptStream) flush() ([]byte, error) {
	return flushStack(es.streams)
}

func makeEncryptStream(settings Settings, seeds seeds, password string, keyfiles []io.Reader) (*encryptStream, error) {
	keys, err := newKeys(settings, seeds, password, keyfiles)
	if err != nil {
		return nil, fmt.Errorf("generating keys: %w", err)
	}
	header := header{
		settings: settings,
		seeds:    seeds,
		refs: refs{
			keyRef:     keys.keyRef,
			keyfileRef: keys.keyfileRef,
			macTag:     [64]byte{}, // will be filled by mac stream
		},
		usesKf:   len(keyfiles) > 0,
		fileSize: 0, // will be filled by size stream
	}

	streams := []streamerFlusher{}

	encryptionStreams, err := newEncryptionStreams(keys, &header)
	if err != nil {
		return nil, fmt.Errorf("creating encryption stream: %w", err)
	}
	streams = append(streams, encryptionStreams...)

	macStream, err := newMacStream(keys, &header, true)
	if err != nil {
		return nil, fmt.Errorf("creating mac stream: %w", err)
	}
	streams = append(streams, macStream)

	ss := makeSizeStream(&header)
	streams = append(streams, &ss)

	if settings.ReedSolomon {
		streams = append(streams, makeRSEncodeStream())
	}

	if settings.Deniability {
		deniabilityStream := newDeniabilityStream(password, &header)
		mockHeaderData := make([]byte, baseHeaderSize+3*len(settings.Comments))
		_, err := deniabilityStream.stream(mockHeaderData)
		if err != nil {
			return nil, fmt.Errorf("seeding deniability stream: %w", err)
		}
		streams = append(streams, deniabilityStream)
	}

	return &encryptStream{
		header:  &header,
		streams: streams,
	}, nil
}
