package rsa

type PrivateKeyInfo struct {
	BitLen int
	Size   int
	Error  string
}

type PublicKeyInfo struct {
	BitLen int
	Size   int
	E      int
}

func (r *FastRSA) MetadataPrivateKey(privateKey string) (*PrivateKeyInfo, error) {

	private, err := r.readPrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	validate := ""
	err = private.Validate()
	if err != nil {
		validate = err.Error()
	}

	info := &PrivateKeyInfo{
		BitLen: private.D.BitLen(),
		Size:   private.Size(),
		Error:  validate,
	}

	return info, nil
}

func (r *FastRSA) MetadataPublicKey(publicKey string) (*PublicKeyInfo, error) {

	public, err := r.readPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	info := &PublicKeyInfo{
		BitLen: public.N.BitLen(),
		Size:   public.Size(),
		E:      public.E,
	}

	return info, nil
}
