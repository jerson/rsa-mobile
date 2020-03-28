package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_SHA1(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha1")
	assert.NoError(t, err)

	t.Log("sha1:", output)
}

func TestFastRSA_MD5(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "md5")
	assert.NoError(t, err)

	t.Log("md5:", output)
}

func TestFastRSA_SHA224(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha224")
	assert.NoError(t, err)

	t.Log("sha224:", output)
}

func TestFastRSA_SHA256(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha256")
	assert.NoError(t, err)

	t.Log("sha256:", output)
}

func TestFastRSA_SHA384(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha384")
	assert.NoError(t, err)

	t.Log("sha384:", output)
}

func TestFastRSA_SHA512(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Hash(inputMessage, "sha512")
	assert.NoError(t, err)

	t.Log("sha512:", output)
}
