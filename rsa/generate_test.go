package rsa

import (
	"testing"
)

func TestOpenPGP_Generate1024(t *testing.T) {

	openPGP := NewFastRSA()
	output, err := openPGP.Generate(1024)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestOpenPGP_Generate2048(t *testing.T) {

	openPGP := NewFastRSA()
	output, err := openPGP.Generate(2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestOpenPGP_Generate4096(t *testing.T) {

	openPGP := NewFastRSA()
	output, err := openPGP.Generate(4096)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
