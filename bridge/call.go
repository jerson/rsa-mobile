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
