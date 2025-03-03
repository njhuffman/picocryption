package picocryption

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"testing"
)

type Example struct {
	decrypted string
	encrypted string
	password  string
	keyfiles  []string
	header    header
}

func encryptWithSeeds(
	seeds seeds,
	in io.Reader,
	password string,
	keyfiles []io.Reader,
	settings Settings,
	out io.Writer,
) ([]byte, error) {
	encryptor, err := newEncryptor(out, settings, seeds, password, keyfiles)
	if err != nil {
		return nil, fmt.Errorf("creating encryptor: %w", err)
	}
	buf := make([]byte, readSize)
	for {
		eof := false
		n, err := in.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				eof = true
			} else {
				return nil, fmt.Errorf("reading input: %w", err)
			}
		}
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

func makeExample(
	decrypted string,
	encrypted string,
	password string,
	keyfiles []string,
) (Example, error) {
	r, err := os.Open("examples/" + encrypted)
	if err != nil {
		return Example{}, err
	}
	defer r.Close()
	header, err := getHeader(r, password)
	if err != nil {
		return Example{}, err
	}
	log.Println("Header:", header)
	return Example{decrypted, encrypted, password, keyfiles, header}, nil
}

func testEncryption(example Example, t *testing.T) {
	kf := []io.Reader{}
	for _, name := range example.keyfiles {
		k, err := os.Open("examples/" + name)
		if err != nil {
			t.Fatal("opening keyfile: %w", err)
		}
		defer k.Close()
		kf = append(kf, k)
	}

	d, err := getDecryptedData(example)
	if err != nil {
		t.Fatal("reading decrypted data: %w", err)
	}
	r := bytes.NewBuffer(d)
	headless := bytes.NewBuffer([]byte{})

	header, err := encryptWithSeeds(
		example.header.seeds,
		r,
		example.password,
		kf,
		example.header.settings,
		headless,
	)
	if err != nil {
		t.Fatal("encrypting data", err)
	}

	headed := bytes.NewBuffer([]byte{})
	err = PrependHeader(headless, headed, header)
	if err != nil {
		t.Fatal("adding header:", err)
	}

	result, err := io.ReadAll(headed)
	if err != nil {
		t.Fatal("extracting result:", err)
	}
	expected, err := getEncryptedData(example)
	if err != nil {
		t.Fatal("reading encrypted data: %w", err)
	}
	if !bytes.Equal(result, expected) {
		log.Println("Len result:  ", len(result))
		log.Println("Len expected:", len(expected))
		for i := 0; i < len(result); i++ {
			if result[i] != expected[i] {
				log.Println("first err at ", i)
				break
			}
		}
		t.Fatal("encrypted data does not match")
	}

}

func testDecryption(example Example, t *testing.T) {
	r, err := os.Open("examples/" + example.encrypted)
	if err != nil {
		t.Fatal("opening decrypted file: %w", err)
	}
	defer r.Close()

	kf := []io.Reader{}
	for _, name := range example.keyfiles {
		k, err := os.Open("examples/" + name)
		if err != nil {
			t.Fatal("opening keyfile: %w", err)
		}
		defer k.Close()
		kf = append(kf, k)
	}

	w := bytes.NewBuffer([]byte{})
	damaged, err := Decrypt(example.password, kf, r, w, false, false, nil)
	if damaged {
		t.Fatal("damaged data")
	}
	if err != nil {
		t.Fatal("decrypting:", err)
	}
	result, err := io.ReadAll(w)
	if err != nil {
		t.Fatal("extracting result:", err)
	}

	expected, err := getDecryptedData(example)
	if err != nil {
		t.Fatal("reading decrypted file: %w", err)
	}
	if !bytes.Equal(result, expected) {
		log.Println("Len result:  ", len(result))
		log.Println("Len expected:", len(expected))
		log.Println("Start of result:", result[:10])
		log.Println("Start of expected:", expected[:10])
		t.Fatal("decrypted data does not match")
	}
}

func getDecryptedData(example Example) ([]byte, error) {
	r, err := os.Open("examples/" + example.decrypted)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func getEncryptedData(example Example) ([]byte, error) {
	r, err := os.Open("examples/" + example.encrypted)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func TestCompatibility001(t *testing.T) {
	example, err := makeExample("empty.txt", "test001.txt.pcv", "abc123", []string{})
	if err != nil {
		t.Fatal("loading example:", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility002(t *testing.T) {
	// Testing standard settings on file that requires near-1Mb flag
	example, err := makeExample("random1048570", "test002.pcv", "qwerty", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility003(t *testing.T) {
	// Testing paranoid mode
	example, err := makeExample("random1048570", "test003.pcv", "I'm not paranoid, you are", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility004(t *testing.T) {
	// Testing comments
	example, err := makeExample("random1048570", "test004.pcv", "comment-test!", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testEncryption(example, t)
	testDecryption(example, t)
}

func TestCompatibility005(t *testing.T) {
	// Testing deniability
	example, err := makeExample("random1048570", "test005.pcv", "=-0987654321`+_)(*&^%$#@!~", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility006(t *testing.T) {
	// Testing reed solomon
	example, err := makeExample("random1048570", "test006.pcv", "\\][|}{", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility007(t *testing.T) {
	// Testing paranoid + reed solomon + deniability on file that includes near-1MiB flag
	example, err := makeExample("random1048570", "test007.pcv", "qazwsx", []string{})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}

func TestCompatibility008(t *testing.T) {
	// Testing ordered keyfiles
	example, err := makeExample("random1048570", "test008.pcv", ",./<>?", []string{"keyfile1.key", "keyfile2.key"})
	if err != nil {
		t.Fatal("loading example: ", err)
	}
	testDecryption(example, t)
	testEncryption(example, t)
}
