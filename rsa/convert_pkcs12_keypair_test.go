package rsa

import (
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_ConvertPKCS12ToKeyPair(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.ConvertPKCS12ToKeyPair(p12, passphrase)
	assert.NoError(t, err)

	encoded, _ := json.MarshalIndent(output, "", " ")
	t.Log("output:", string(encoded))
}

func TestFastRSA_ConvertPKCS12ToKeyPairComplete(t *testing.T) {

	instance := NewFastRSA()
	keyPair, err := instance.ConvertPKCS12ToKeyPair(p12, passphrase)
	assert.NoError(t, err)

	output, err := instance.ConvertKeyPairToPKCS12(keyPair.PrivateKey, keyPair.PublicKey, keyPair.Certificate, passphrase)
	assert.NoError(t, err)

	// TODO fixme
	// assert.Equal(t, strings.TrimSpace(p12), strings.TrimSpace(output))

	t.Log("output:", output)
}
