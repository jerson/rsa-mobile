package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_SignPKCS1v15(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.SignPKCS1v15(inputMessage, "sha512", privateKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
