package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_EncryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptPKCS1v15(inputMessage, publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_EncryptPKCS1v15WrongKey(t *testing.T) {
	instance := NewFastRSA()
	_, err := instance.EncryptPKCS1v15(inputMessage, "nop")
	assert.Error(t, err)
}

func TestFastRSA_EncryptPKCS1v15BytesBigMessage(t *testing.T) {
	instance := NewFastRSA()
	inputMessage := getBigInputMessage()
	output, err := instance.EncryptPKCS1v15Bytes([]byte(inputMessage), publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
