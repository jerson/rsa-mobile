package rsa

import (
	"testing"
)

func TestFastRSA_SignPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.SignPSS(inputMessage, "sha512", "equalsHash", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
