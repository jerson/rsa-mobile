package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_DecryptOAEP(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.DecryptOAEP(cipherTextOAEP, "", "sha256", privateKey)
	assert.NoError(t, err)

	t.Log("output:", output)
}
