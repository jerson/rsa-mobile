package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_DecryptPKCS1v15(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptPKCS1v15(cipherText, privateKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
