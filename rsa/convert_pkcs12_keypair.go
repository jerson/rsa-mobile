package rsa

type PKCS12KeyPair struct {
	PrivateKey  string
	PublicKey   string
	Certificate string
}

func (r *FastRSA) ConvertPKCS12ToKeyPair(pkcs12, password string) (*PKCS12KeyPair, error) {

	var keyPair *PKCS12KeyPair
	key, certificate, err := r.readPKCS12(pkcs12, password)
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
		certificateBytes, err := encodeCertificate(certificate)
		if err != nil {
			return nil, err
		}
		certificateEncoded = string(certificateBytes)
	}
	keyPair = &PKCS12KeyPair{
		PrivateKey:  string(privateKey),
		PublicKey:   publicKeyEncoded,
		Certificate: certificateEncoded,
	}

	return keyPair, nil
}
