package rsa

import "testing"

func TestFastRSA_EncryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptPKCS1v15(inputMessage, p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
