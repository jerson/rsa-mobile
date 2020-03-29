package rsa

func (r *FastRSA) ConvertPublicKeyToPKIX(publicKey string) (string, error) {

	publicKeyCertKeyBase, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := encodePublicKey(publicKeyCertKeyBase, PublicKeyFormatTypePKIX)
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func (r *FastRSA) ConvertPublicKeyToPKCS1(publicKey string) (string, error) {

	publicKeyCertKeyBase, err := r.readPublicKey(publicKey)
	if err != nil {
		return "", err
	}

	output, err := encodePublicKey(publicKeyCertKeyBase, PublicKeyFormatTypePKCS1)
	if err != nil {
		return "", err
	}

	return string(output), nil
}
