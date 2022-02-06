package rsa

import (
	"testing"
)

func TestFastRSA_DecryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptOAEP(cipherTextOAEP, "", "sha256", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_DecryptOAEPBytesBigMessage(t *testing.T) {

	instance := NewFastRSA()
	inputMessage := getBigInputMessage()

	cipherTextOAEP, err := instance.EncryptOAEPBytes([]byte(inputMessage), "", "sha256", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.DecryptOAEPBytes(cipherTextOAEP, "", "sha256", privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", string(output))
}
