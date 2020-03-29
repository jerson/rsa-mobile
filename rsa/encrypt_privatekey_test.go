package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var privateKeyPassword = "123456"

func TestFastRSA_EncryptPrivateKey(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.EncryptPrivateKey(privateKey, privateKeyPassword, "des")
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_EncryptPrivateKeyComplete(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.EncryptPrivateKey(privateKey, privateKeyPassword, "aes256")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := instance.DecryptPrivateKey(output, privateKeyPassword)
	if err != nil {
		t.Fatal(err)
	}

	privateKeyConverted, err := instance.ConvertPrivateKeyToPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, privateKeyConverted, decrypted)

	t.Log("output:", output)
}
