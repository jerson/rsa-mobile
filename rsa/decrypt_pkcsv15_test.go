package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_DecryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptPKCS1v15(cipherText, privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_DecryptPKCS1v15WrongPrivate(t *testing.T) {
	instance := NewFastRSA()
	_, err := instance.DecryptPKCS1v15(cipherText, "nop")
	assert.Error(t, err)
}
