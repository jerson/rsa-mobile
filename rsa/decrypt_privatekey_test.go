package rsa

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var privateKeyEncrypted = `-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,D9EBC1DB488E6D39

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
-----END RSA PRIVATE KEY-----
`

func TestFastRSA_DecryptPrivateKey(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.DecryptPrivateKey(privateKeyEncrypted, privateKeyPassword)
	if err != nil {
		t.Fatal(err)
	}

	t.Log("output:", output)
}
func TestFastRSA_DecryptPrivateKeyComplete(t *testing.T) {
	instance := NewFastRSA()
	output, err := instance.DecryptPrivateKey(privateKeyEncrypted, privateKeyPassword)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := instance.EncryptPrivateKey(output, privateKeyPassword, "3des")
	if err != nil {
		t.Fatal(err)
	}
	decrypted, err := instance.DecryptPrivateKey(encrypted, privateKeyPassword)
	if err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, decrypted, output)

	t.Log("output:", output)
}
