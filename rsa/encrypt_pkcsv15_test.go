package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_EncryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptPKCS1v15(inputMessage, publicKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
