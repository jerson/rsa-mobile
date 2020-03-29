package rsa

type PKCS12KeyPair struct {
	PublicKey   string
	PrivateKey  string
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

	certificateEncoded := encodeCertificate(certificate)
	keyPair = &PKCS12KeyPair{
		PublicKey:   publicKeyEncoded,
		PrivateKey:  string(privateKey),
		Certificate: string(certificateEncoded),
	}

	return keyPair, nil
}
