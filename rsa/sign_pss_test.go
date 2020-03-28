package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_SignPSS(t *testing.T) {

	instance := NewFastRSA()

	output, err := instance.SignPSS(inputMessage, "sha512", "auto", privateKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
