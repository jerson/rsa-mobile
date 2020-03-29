package rsa

import (
	"encoding/json"
	"testing"
)

func TestFastRSA_ConvertPKCS12ToKeyPair(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.ConvertPKCS12ToKeyPair(p12, password)
	if err != nil {
		t.Fatal(err)
	}

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertPKCS12ToKeyPairComplete(t *testing.T) {

	instance := NewFastRSA()
	keyPair, err := instance.ConvertPKCS12ToKeyPair(p12, password)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertKeyPairToPKCS12(keyPair.PrivateKey, keyPair.Certificate, password)
	if err != nil {
		t.Fatal(err)
	}

	// TODO fixme
	// assert.Equal(t, strings.TrimSpace(p12), strings.TrimSpace(output))

	t.Log("output:", output)
}
