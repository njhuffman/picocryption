package picocryption

import (
	"io"
	"os"
	"testing"
)

func TestDecryptStream(t *testing.T) {
	r, err := os.Open("examples/test006.pcv")
	if err != nil {
		t.Fatal("opening file:", err)
	}

	password := "random1048570"
	damageTracker := damageTracker{}
	s := makeDecryptStream(password, nil, &damageTracker)
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal("reading file:", err)
	}
	p, err := s.stream(data)
	if err != nil {
		t.Fatal("streaming:", err)
	}
	t.Fatal("Length of p:", len(p))
}

func TestEncryptStream(t *testing.T) {
	data := []byte("Hello, World!")
	settings := Settings{}
	seeds, err := randomSeeds()
	if err != nil {
		t.Fatal("generating seeds:", err)
	}
	password := "password"
	s, err := makeEncryptStream(settings, seeds, password)
	if err != nil {
		t.Fatal("making encrypt stream:", err)
	}
	p, err := s.stream(data)
	t.Fatal("Length of p:", len(p))
}
