package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestFastRSA_ConvertPrivateKeyToPKCS1(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.ConvertPrivateKeyToPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertPrivateKeyToPKCS8(t *testing.T) {

	instance := NewFastRSA()
	output, err := instance.ConvertPrivateKeyToPKCS8(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}

func TestFastRSA_ConvertPrivateKey(t *testing.T) {

	instance := NewFastRSA()
	output1, err := instance.ConvertPrivateKeyToPKCS8(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	output2, err := instance.ConvertPrivateKeyToPKCS1(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotEqual(t, output1, output2)

}
