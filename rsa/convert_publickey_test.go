package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_ConvertPublicKeyToPKCS1(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertPublicKeyToPKCS1(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertPublicKeyToPKIX(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertPublicKeyToPKIX(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertPublicKeyToJWK(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertPublicKeyToJWK(publicKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertPublicKey(t *testing.T) {

	instance := NewFastRSA()
	output1, err := instance.ConvertPublicKeyToPKIX(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	output2, err := instance.ConvertPublicKeyToPKCS1(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, output1, output2)

}
