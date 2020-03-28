package rsa

import (
	"crypto"
	"crypto/md5"
	cryptoRSA "crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/keybase/go-crypto/pkcs12"
	"github.com/keybase/go-crypto/rsa"
	"hash"
)

func hashTo(hash string) crypto.Hash {
	switch hash {
	case "sha256":
		return crypto.SHA256
	case "sha224":
		return crypto.SHA224
	case "sha384":
		return crypto.SHA384
	case "sha512":
		return crypto.SHA512
	case "sha1":
		return crypto.SHA1
	case "md5":
		return crypto.MD5
	default:
		return crypto.SHA256
	}
}

func getHashInstance(name string) hash.Hash {
	switch name {
	case "md5":
		return md5.New()
	case "sha1":
		return sha1.New()
	case "sha224":
		return sha512.New512_224()
	case "sha256":
		return sha256.New()
	case "sha384":
		return sha512.New384()
	case "sha512":
		return sha512.New()
	default:
		return sha256.New()
	}
}

func toCryptoRSA(keybasePrivateKey *rsa.PrivateKey) *cryptoRSA.PrivateKey {

	var crtValues []cryptoRSA.CRTValue
	for _, value := range keybasePrivateKey.Precomputed.CRTValues {
		crtValues = append(crtValues, cryptoRSA.CRTValue{
			Exp:   value.Exp,
			Coeff: value.Coeff,
			R:     value.R,
		})
	}

	privateKey := &cryptoRSA.PrivateKey{
		PublicKey: cryptoRSA.PublicKey{
			N: keybasePrivateKey.PublicKey.N,
			E: int(keybasePrivateKey.PublicKey.E),
		},
		D:      keybasePrivateKey.D,
		Primes: keybasePrivateKey.Primes,
		Precomputed: cryptoRSA.PrecomputedValues{
			Dp:        keybasePrivateKey.Precomputed.Dp,
			Dq:        keybasePrivateKey.Precomputed.Dq,
			Qinv:      keybasePrivateKey.Precomputed.Qinv,
			CRTValues: crtValues,
		},
	}
	return privateKey
}

func toKeyBaseRSA(cryptoPrivateKey *cryptoRSA.PrivateKey) *rsa.PrivateKey {

	var crtValues []rsa.CRTValue
	for _, value := range cryptoPrivateKey.Precomputed.CRTValues {
		crtValues = append(crtValues, rsa.CRTValue{
			Exp:   value.Exp,
			Coeff: value.Coeff,
			R:     value.R,
		})
	}

	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: cryptoPrivateKey.PublicKey.N,
			E: int64(cryptoPrivateKey.PublicKey.E),
		},
		D:      cryptoPrivateKey.D,
		Primes: cryptoPrivateKey.Primes,
		Precomputed: rsa.PrecomputedValues{
			Dp:        cryptoPrivateKey.Precomputed.Dp,
			Dq:        cryptoPrivateKey.Precomputed.Dq,
			Qinv:      cryptoPrivateKey.Precomputed.Qinv,
			CRTValues: crtValues,
		},
	}
	return privateKey
}

func generateKeyPair(keybaseRSA *cryptoRSA.PrivateKey) *KeyPair {
	privateKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(keybaseRSA),
		},
	)
	publicKey := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(&keybaseRSA.PublicKey),
		},
	)
	return &KeyPair{
		PublicKey:  string(publicKey),
		PrivateKey: string(privateKey),
	}

}

func (r *FastRSA) readPKCS12(data, passphrase string) (*rsa.PrivateKey, *x509.Certificate, error) {

	decoded, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, nil, err
	}
	private, certificate, err := pkcs12.Decode(decoded, passphrase)
	if err != nil {
		return nil, certificate, err
	}

	privateKey := toKeyBaseRSA(private.(*cryptoRSA.PrivateKey))
	if err := privateKey.Validate(); err != nil {
		return privateKey, certificate, err
	}

	return privateKey, certificate, nil
}
