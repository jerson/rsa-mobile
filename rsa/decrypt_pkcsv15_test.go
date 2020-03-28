package rsa

import "testing"

func TestFastRSA_DecryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptPKCS1v15(ciphertext, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
