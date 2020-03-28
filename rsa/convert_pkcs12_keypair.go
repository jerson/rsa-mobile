package rsa

func (r *FastRSA) ConvertPKCS12ToKeyPair(pkcs12, passphrase string) (*KeyPair, error) {

	var keyPair *KeyPair
	key, _, err := r.readPKCS12(pkcs12, passphrase)
	if err != nil {
		return nil, err
	}

	keybaseRSA := toCryptoRSA(key)
	keyPair = generateKeyPair(keybaseRSA)

	return keyPair, nil
}
