package rsa

import (
	"encoding/json"
	"testing"
)

func TestFastRSA_EncryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptOAEP(inputMessage, "", "sha256", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_EncryptOAEPBytesBigMessage(t *testing.T) {

	inputMessage := getBigInputMessage()
	instance := NewFastRSA()
	metadata, err := instance.MetadataPublicKey(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(metadata)
	t.Log(string(data))
	output, err := instance.EncryptOAEPBytes([]byte(inputMessage), "", "sha256", publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
