package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_EncryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.EncryptOAEP(inputMessage, "", "sha256", publicKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
