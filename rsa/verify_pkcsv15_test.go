package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_VerifyPKCS1v15(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.VerifyPKCS1v15(signed, inputMessage, "sha512", publicKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
