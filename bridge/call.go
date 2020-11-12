package rsaBridge

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/jerson/rsa-mobile/bridge/model"
	"github.com/jerson/rsa-mobile/rsa"
)

// Call ...
func Call(name string, payload []byte) ([]byte, error) {

	instance := NewInstance()
	var output proto.Message
	switch name {
	case "convertJWKToPrivateKey":
		output = instance.convertJWKToPrivateKey(payload)
	case "convertJWKToPublicKey":
		output = instance.convertJWKToPublicKey(payload)
	case "convertKeyPairToPKCS12":
		output = instance.convertKeyPairToPKCS12(payload)
	case "convertPKCS12ToKeyPair":
		output = instance.convertPKCS12ToKeyPair(payload)
	case "convertPrivateKeyToPKCS8":
		output = instance.convertPrivateKeyToPKCS8(payload)
	case "convertPrivateKeyToPKCS1":
		output = instance.convertPrivateKeyToPKCS1(payload)
	case "convertPrivateKeyToJWK":
		output = instance.convertPrivateKeyToJWK(payload)
	case "convertPrivateKeyToPublicKey":
		output = instance.convertPrivateKeyToPublicKey(payload)
	case "convertPublicKeyToPKIX":
		output = instance.convertPublicKeyToPKIX(payload)
	case "convertPublicKeyToPKCS1":
		output = instance.convertPublicKeyToPKCS1(payload)
	case "convertPublicKeyToJWK":
		output = instance.convertPublicKeyToJWK(payload)
	case "decryptOAEP":
		output = instance.decryptOAEP(payload)
	case "decryptOAEPBytes":
		output = instance.decryptOAEPBytes(payload)
	case "decryptPKCS1v15":
		output = instance.decryptPKCS1v15(payload)
	case "decryptPKCS1v15Bytes":
		output = instance.decryptPKCS1v15Bytes(payload)
	case "decryptPrivateKey":
		output = instance.decryptPrivateKey(payload)
	case "encryptOAEP":
		output = instance.encryptOAEP(payload)
	case "encryptOAEPBytes":
		output = instance.encryptOAEPBytes(payload)
	case "encryptPKCS1v15":
		output = instance.encryptPKCS1v15(payload)
	case "encryptPKCS1v15Bytes":
		output = instance.encryptPKCS1v15Bytes(payload)
	case "encryptPrivateKey":
		output = instance.encryptPrivateKey(payload)
	case "generate":
		output = instance.generate(payload)
	case "hash":
		output = instance.hash(payload)
	case "base64":
		output = instance.base64(payload)
	case "metadataPrivateKey":
		output = instance.metadataPrivateKey(payload)
	case "metadataPublicKey":
		output = instance.metadataPublicKey(payload)
	case "signPKCS1v15":
		output = instance.signPKCS1v15(payload)
	case "signPKCS1v15Bytes":
		output = instance.signPKCS1v15Bytes(payload)
	case "signPSS":
		output = instance.signPSS(payload)
	case "signPSSBytes":
		output = instance.signPSSBytes(payload)
	case "verifyPKCS1v15":
		output = instance.verifyPKCS1v15(payload)
	case "verifyPKCS1v15Bytes":
		output = instance.verifyPKCS1v15Bytes(payload)
	case "verifyPSS":
		output = instance.verifyPSS(payload)
	case "verifyPSSBytes":
		output = instance.verifyPSSBytes(payload)
	default:
		return nil, fmt.Errorf("not implemented: %s", name)
	}

	return proto.Marshal(output)
}

type instance struct {
	instance *rsa.FastRSA
}

func NewInstance() *instance {
	return &instance{instance: rsa.NewFastRSA()}
}

func (m instance) convertJWKToPrivateKey(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertJWTRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertJWKToPrivateKey(request.Data, request.KeyId)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertJWKToPublicKey(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertJWTRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertJWKToPublicKey(request.Data, request.KeyId)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertKeyPairToPKCS12(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertKeyPairRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertKeyPairToPKCS12(request.PrivateKey, request.Certificate, request.Password)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPKCS12ToKeyPair(payload []byte) proto.Message {
	response := &model.PKCS12KeyPairResponse{}
	request := &model.ConvertPKCS12Request{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPKCS12ToKeyPair(request.Pkcs12, request.Password)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = &model.PKCS12KeyPair{
		PrivateKey:  output.PrivateKey,
		PublicKey:   output.PublicKey,
		Certificate: output.Certificate,
	}
	return response
}

func (m instance) convertPrivateKeyToPKCS8(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPrivateKeyToPKCS8(request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPrivateKeyToPKCS1(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPrivateKeyToPKCS1(request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPrivateKeyToJWK(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPrivateKeyToJWK(request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPrivateKeyToPublicKey(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPrivateKeyToPublicKey(request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPublicKeyToPKIX(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPublicKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPublicKeyToPKIX(request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPublicKeyToPKCS1(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPublicKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPublicKeyToPKCS1(request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) convertPublicKeyToJWK(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.ConvertPublicKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.ConvertPublicKeyToJWK(request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) decryptOAEP(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.DecryptOAEPRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptOAEP(request.Ciphertext, request.Label, m.parseHash(request.Hash), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response

}

func (m instance) decryptOAEPBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.DecryptOAEPBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptOAEPBytes(request.Ciphertext, request.Label, m.parseHash(request.Hash), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) decryptPKCS1v15(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.DecryptPKCS1V15Request{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptPKCS1v15(request.Ciphertext, request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) decryptPKCS1v15Bytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.DecryptPKCS1V15BytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptPKCS1v15Bytes(request.Ciphertext, request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) decryptPrivateKey(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.DecryptPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.DecryptPrivateKey(request.PrivateKeyEncrypted, request.Password)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptOAEP(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptOAEPRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptOAEP(request.Message, request.Label, m.parseHash(request.Hash), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptOAEPBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.EncryptOAEPBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptOAEPBytes(request.Message, request.Label, m.parseHash(request.Hash), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptPKCS1v15(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptPKCS1V15Request{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptPKCS1v15(request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptPKCS1v15Bytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.EncryptPKCS1V15BytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptPKCS1v15Bytes(request.Message, request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) encryptPrivateKey(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptPrivateKey(request.PrivateKey, request.Password, m.parsePEMCipher(request.Cipher))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) generate(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.EncryptPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.EncryptPrivateKey(request.PrivateKey, request.Password, m.parsePEMCipher(request.Cipher))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) hash(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.HashRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Hash(request.Message, m.parseHash(request.Hash))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) base64(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.HashRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Hash(request.Message, m.parseHash(request.Hash))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) metadataPrivateKey(payload []byte) proto.Message {
	response := &model.PrivateKeyInfoResponse{}
	request := &model.MetadataPrivateKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.MetadataPrivateKey(request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = &model.PrivateKeyInfo{
		BitLen: int64(output.BitLen),
		Size_:  int64(output.Size),
		Error:  output.Error,
	}
	return response
}

func (m instance) metadataPublicKey(payload []byte) proto.Message {
	response := &model.PublicKeyInfoResponse{}
	request := &model.MetadataPublicKeyRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.MetadataPublicKey(request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = &model.PublicKeyInfo{
		BitLen: int64(output.BitLen),
		Size_:  int64(output.Size),
		E:      int64(output.E),
	}
	return response
}

func (m instance) signPKCS1v15(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.SignPKCS1V15Request{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignPKCS1v15(request.Message, m.parseHash(request.Hash), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) signPKCS1v15Bytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.SignPKCS1V15BytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignPKCS1v15Bytes(request.Message, m.parseHash(request.Hash), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) signPSS(payload []byte) proto.Message {
	response := &model.StringResponse{}
	request := &model.SignPSSRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignPSS(request.Message, m.parseHash(request.Hash), m.parseSaltLength(request.SaltLength), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) signPSSBytes(payload []byte) proto.Message {
	response := &model.BytesResponse{}
	request := &model.SignPSSBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.SignPSSBytes(request.Message, m.parseHash(request.Hash), m.parseSaltLength(request.SaltLength), request.PrivateKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) verifyPKCS1v15(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyPKCS1V15Request{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.VerifyPKCS1v15(request.Signature, request.Message, m.parseHash(request.Hash), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) verifyPKCS1v15Bytes(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyPKCS1V15BytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.VerifyPKCS1v15Bytes(request.Signature, request.Message, m.parseHash(request.Hash), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) verifyPSS(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyPSSRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.VerifyPSS(request.Signature, request.Message, m.parseHash(request.Hash), m.parseSaltLength(request.SaltLength), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) verifyPSSBytes(payload []byte) proto.Message {
	response := &model.BoolResponse{}
	request := &model.VerifyPSSBytesRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.VerifyPSSBytes(request.Signature, request.Message, m.parseHash(request.Hash), m.parseSaltLength(request.SaltLength), request.PublicKey)
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output
	return response
}

func (m instance) parseHash(input model.Hash) string {
	switch input {
	case model.Hash_HASH_MD5:
		return "md5"
	case model.Hash_HASH_SHA1:
		return "sha1"
	case model.Hash_HASH_SHA224:
		return "sha224"
	case model.Hash_HASH_SHA384:
		return "sha384"
	case model.Hash_HASH_SHA512:
		return "sha512"
	case model.Hash_HASH_SHA256:
		fallthrough
	case model.Hash_HASH_UNSPECIFIED:
		fallthrough
	default:
		return "sha256"
	}
}

func (m instance) parseSaltLength(input model.SaltLength) string {
	switch input {
	case model.SaltLength_SALTLENGTH_EQUALS_HASH:
		return "equalsHash"
	case model.SaltLength_SALTLENGTH_AUTO:
		fallthrough
	case model.SaltLength_SALTLENGTH_UNSPECIFIED:
		fallthrough
	default:
		return "auto"
	}
}
func (m instance) parsePEMCipher(input model.PEMCipher) string {
	switch input {
	case model.PEMCipher_PEMCIPHER_DES:
		return "des"
	case model.PEMCipher_PEMCIPHER_3DES:
		return "3des"
	case model.PEMCipher_PEMCIPHER_AES128:
		return "aes128"
	case model.PEMCipher_PEMCIPHER_AES192:
		return "aes192"
	case model.PEMCipher_PEMCIPHER_AES256:
		fallthrough
	case model.PEMCipher_PEMCIPHER_UNSPECIFIED:
		fallthrough
	default:
		return "aes256"
	}
}
