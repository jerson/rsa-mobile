package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_Generate1024(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(1024)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_Generate2048(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(2048)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_Generate4096(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(4096)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_Generate1024Extract(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.Generate(1024)
	if err != nil {
		t.Fatal(err)
	}

	result, err := instance.ConvertPrivateKeyToPublicKey(output.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, output.PublicKey, result)
	t.Log("output:", output)
}
