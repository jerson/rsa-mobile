package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_VerifyPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.VerifyPSS(signedPSS, inputMessage, "sha512", "auto", publicKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
