package picocryption

import (
	"errors"
	"fmt"
	"io"
	"time"
)

const readSize = 1 << 20
const maxCommentsLength = 99999

var ErrFileTooShort = errors.New("file too short")
var ErrIncorrectPassword = errors.New("incorrect password")
var ErrIncorrectKeyfiles = errors.New("incorrect keyfiles")
var ErrIncorrectOrMisorderedKeyfiles = errors.New("incorrect or misordered keyfiles")
var ErrKeyfilesRequired = errors.New("missing required keyfiles")
var ErrDuplicateKeyfiles = errors.New("duplicate keyfiles")
var ErrKeyfilesNotRequired = errors.New("keyfiles not required")
var ErrCorrupted = errors.New("data corrupted beyond repair")
var ErrCommentsTooLong = errors.New("comments exceed maximum length")

type Settings struct {
	Comments    string
	ReedSolomon bool
	Paranoid    bool
	OrderedKf   bool
	Deniability bool
}

type Update struct {
	Status string
	Bps    int
	Total  int
}

func Decrypt(
	pw string,
	kf []io.Reader,
	r io.Reader,
	w io.Writer,
	skipReedSolomon bool,
	ignoreCorruption bool,
	update chan Update,
) (bool, error) {

	decryptStream := makeDecryptStream(pw)

	getNow := func() float64 { return float64(time.Now().UnixMilli()) / 1000.0 }
	start := getNow()
	count := 0
	total := 0
	corruptionIgnored := false
	for {
		now := getNow()
		if now-start > 1.0 {
			if update != nil {
				update <- Update{"Decrypting", int(float64(count) / (now - start)), total}
			}
			count = 0
			start = now
		}

		p := make([]byte, readSize)
		n, err := r.Read(p)
		eof := false
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
			} else {
				return false, fmt.Errorf("reading input: %w", err)
			}
		}
		p, damaged, err := decryptStream.stream(p[:n])
		if err != nil {
			if errors.Is(err, ErrCorrupted) && ignoreCorruption {
				corruptionIgnored = true
			} else {
				return damaged, err
			}
		}
		_, err = w.Write(p)
		if err != nil {
			return damaged, err
		}
		count += len(p)
		total += len(p)
		if eof {
			if corruptionIgnored {
				return damaged, ErrCorrupted
			}
			p, dmg, err := decryptStream.flush()
			damaged = damaged || dmg
			if err != nil {
				return damaged, err
			}
			_, err = w.Write(p)
			if err != nil {
				return damaged, err
			}
			return damaged, nil
		}
	}
}

func GetEncryptionSettings(r io.Reader) (Settings, error) {
	header, _, err := readHeader(r, "")
	if err == nil {
		return header.settings, nil
	}
	if errors.Is(err, ErrCorrupted) {
		return Settings{Deniability: true}, nil
	}
	return Settings{}, fmt.Errorf("reading header: %w", err)
}

func EncryptHeadless(
	in io.Reader,
	password string,
	keyfiles []io.Reader,
	settings Settings,
	out io.Writer,
	update chan Update,
) ([]byte, error) {
	if len(settings.Comments) > maxCommentsLength {
		return nil, ErrCommentsTooLong
	}
	if update != nil {
		update <- Update{"Building encryption block", 0, 0}
	}
	seeds, err := randomSeeds()
	if err != nil {
		return nil, fmt.Errorf("generating seeds: %w", err)
	}

	encryptor, err := newEncryptor(out, settings, seeds, password, keyfiles)
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}

	getNow := func() float64 { return float64(time.Now().UnixMilli()) / 1000.0 }
	start := getNow()
	count := 0
	total := 0
	buf := make([]byte, readSize)
	for {
		now := getNow()
		if now-start > 1.0 {
			if update != nil {
				update <- Update{"Encrypting", int(float64(count) / (now - start)), total}
			}
			count = 0
			start = now
		}
		eof := false
		n, err := in.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
			} else {
				return nil, fmt.Errorf("reading input: %w", err)
			}
		}
		count += n
		total += n
		err = encryptor.write(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("encrypting input: %w", err)
		}
		if eof {
			break
		}
	}

	err = encryptor.close()
	if err != nil {
		return nil, fmt.Errorf("closing encryptor: %w", err)
	}

	header, err := encryptor.makeHeader()
	if err != nil {
		return header, fmt.Errorf("making header: %w", err)
	}
	return header, nil
}

func PrependHeader(
	headless io.Reader,
	headed io.Writer,
	header []byte,
) error {
	_, err := headed.Write(header)
	if err != nil {
		return fmt.Errorf("writing header: %w", err)
	}

	for {
		data := make([]byte, readSize)
		n, err := headless.Read(data)
		eof := err == io.EOF
		if (err != nil) && (err != io.EOF) {
			return fmt.Errorf("reading body data: %w", err)
		}
		data = data[:n]

		_, err = headed.Write(data)
		if err != nil {
			return fmt.Errorf("writing body data: %w", err)
		}

		if eof {
			break
		}
	}
	return nil
}

func HeaderSize(settings Settings) int {
	size := baseHeaderSize + 3*len(settings.Comments)
	if settings.Deniability {
		size += len(seeds{}.denyNonce) + len(seeds{}.denySalt)
	}
	return size
}
