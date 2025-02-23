package picocryption

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"testing"
)

func TestFileTooShort(t *testing.T) {
	for size := range []int{0, 10, 100} {
		invalidData := make([]byte, size)
		_, err := rand.Read(invalidData)
		if err != nil {
			t.Fatal("creating random data:", err)
		}
		_, err = Decrypt("password", []io.Reader{}, bytes.NewBuffer(invalidData), bytes.NewBuffer([]byte{}), false, false, nil)
		if !errors.Is(err, ErrFileTooShort) {
			t.Fatal("expected ErrFileTooShort, got", err)
		}
	}
}

func TestFileCorrupted(t *testing.T) {
	invalidData := make([]byte, 1000)
	_, err := rand.Read(invalidData)
	if err != nil {
		t.Fatal("creating random data:", err)
	}
	_, err = Decrypt("password", []io.Reader{}, bytes.NewBuffer(invalidData), bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrCorrupted) {
		t.Fatal("expected ErrCorrupted, got", err)
	}
}

func TestIncorrectPassword(t *testing.T) {
	reader, err := os.Open("examples/test001.txt.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("wrong-password", []io.Reader{}, reader, bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrIncorrectPassword) {
		t.Fatal("expected wrong password, got", err)
	}
}

func TestIncorrectKeyfiles(t *testing.T) {
	reader, err := os.Open("examples/test008.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	wrongKeyfileData := make([]byte, 100)
	rand.Read(wrongKeyfileData)
	defer reader.Close()
	_, err = Decrypt(",./<>?", []io.Reader{bytes.NewBuffer(wrongKeyfileData)}, reader, bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrIncorrectOrMisorderedKeyfiles) {
		t.Fatal("expected wrong password, got", err)
	}
}

func TestKeyfilesRequired(t *testing.T) {
	reader, err := os.Open("examples/test008.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt(",./<>?", []io.Reader{}, reader, bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrKeyfilesRequired) {
		t.Fatal("expected wrong password, got", err)
	}
}

func TestDuplicateKeyfiles(t *testing.T) {
	keyfileData := make([]byte, 100)
	rand.Read(keyfileData)
	keyfiles := []io.Reader{}
	for range 2 {
		buff := make([]byte, len(keyfileData))
		copy(buff, keyfileData)
		keyfiles = append(keyfiles, bytes.NewBuffer(buff))
	}
	_, err := EncryptHeadless(
		bytes.NewBuffer([]byte{}),
		"test-password",
		keyfiles,
		Settings{},
		bytes.NewBuffer([]byte{}),
		nil,
	)
	if !errors.Is(err, ErrDuplicateKeyfiles) {
		t.Fatal("expected ErrDuplicateKeyfiles, got", err)
	}
}

func TestKeyfilesNotRequired(t *testing.T) {
	reader, err := os.Open("examples/test002.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("qwerty", []io.Reader{bytes.NewBuffer([]byte{})}, reader, bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrKeyfilesNotRequired) {
		t.Fatal("expected ErrKeyfilesNotRequired, got", err)
	}
}

func TestCorrupted(t *testing.T) {
	reader, err := os.Open("examples/corrupted.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()
	_, err = Decrypt("qwerty", []io.Reader{}, reader, bytes.NewBuffer([]byte{}), false, false, nil)
	if !errors.Is(err, ErrCorrupted) {
		t.Fatal("expected ErrCorrupted, got", err)
	}
}

func TestDamagedButRecoverable(t *testing.T) {
	reader, err := os.Open("examples/test006.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}
	defer reader.Close()

	encryptedData, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal("reading file:", err)
	}

	encryptedData[1000] = byte(int(encryptedData[1000]) + 1)

	damaged, err := Decrypt("\\][|}{", []io.Reader{}, bytes.NewBuffer(encryptedData), bytes.NewBuffer([]byte{}), false, false, nil)
	if err != nil {
		t.Fatal("expected no error, got", err)
	}
	if !damaged {
		t.Fatal("expected damage")
	}
}

func TestCommentsTooLong(t *testing.T) {
	comments := make([]byte, maxCommentsLength+1)
	_, err := EncryptHeadless(
		bytes.NewBuffer([]byte{}),
		"test-password",
		[]io.Reader{},
		Settings{Comments: string(comments)},
		bytes.NewBuffer([]byte{}),
		nil,
	)
	if !errors.Is(err, ErrCommentsTooLong) {
		t.Fatal("expected ErrCommentsTooLong, got", err)
	}
}
