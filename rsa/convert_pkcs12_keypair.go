package rsa

type PKCS12KeyPair struct {
	PrivateKey  string
	PublicKey   string
	Certificate string
}

func (r *FastRSA) ConvertPKCS12ToKeyPair(pkcs12, passphrase string) (*PKCS12KeyPair, error) {

	var keyPair *PKCS12KeyPair
	key, certificate, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return nil, err
	}

	privateKey, err := encodePrivateKey(key, PrivateKeyFormatTypePKCS1)
	if err != nil {
		return nil, err
	}
	publicKeySource, err := publicFromPrivate(key)
	publicKeyEncoded := ""
	if publicKeySource != nil {
		publicKey, err := encodePublicKey(publicKeySource, PublicKeyFormatTypePKCS1)
		if err != nil {
			return nil, err
		}
		publicKeyEncoded = string(publicKey)
	}

	certificateEncoded := ""
	if certificate != nil {
		certificateEncoded = string(encodeCertificate(certificate))
	}
	keyPair = &PKCS12KeyPair{
		PrivateKey:  string(privateKey),
		PublicKey:   publicKeyEncoded,
		Certificate: certificateEncoded,
	}

	return keyPair, nil
}
