package rsa

import (
	"testing"
)

func TestFastRSA_SHA1(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha1")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("sha1:", output)
}

func TestFastRSA_MD5(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "md5")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("md5:", output)
}

func TestFastRSA_SHA224(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha224")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("sha224:", output)
}

func TestFastRSA_SHA256(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha256")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("sha256:", output)
}

func TestFastRSA_SHA384(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha384")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("sha384:", output)
}

func TestFastRSA_SHA512(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha512")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("sha512:", output)
}
