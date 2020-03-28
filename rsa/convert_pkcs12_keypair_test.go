package rsa

import (
	"encoding/json"
	"testing"
)

func TestFastRSA_ConvertPKCS12ToKeyPair(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.ConvertPKCS12ToKeyPair(p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertPKCS12ToKeyPairComplete(t *testing.T) {

	instance := NewFastRSA()
	keyPair, err := instance.ConvertPKCS12ToKeyPair(p12, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	output, err := instance.ConvertKeyPairToPKCS12(keyPair.PrivateKey, keyPair.PublicKey, certificate, passphrase)
	if err != nil {
		t.Fatal(err)
	}

	/*p12Normalized := strings.ReplaceAll(p12, "\n", "")
	p12Normalized = strings.ReplaceAll(p12, "\r", "")
	if output != p12Normalized {
		t.Fatal(errors.New("should be equal"))
	}*/

	t.Log("output:", output)
}
