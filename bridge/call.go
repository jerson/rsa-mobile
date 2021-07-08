package rsaBridge

import (
	"fmt"
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/jerson/rsa-mobile/bridge/model"
	"github.com/jerson/rsa-mobile/rsa"
)

// Call ...
func Call(name string, payload []byte) ([]byte, error) {

	instance := NewInstance()
	var output []byte
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

	return output, nil
}

type instance struct {
	instance *rsa.FastRSA
}

func NewInstance() *instance {
	return &instance{instance: rsa.NewFastRSA()}
}

func (m instance) convertJWKToPrivateKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertJWTRequest(payload, 0)

	output, err := m.instance.ConvertJWKToPrivateKey(m.toString(request.Data()), m.toString(request.KeyId()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertJWKToPublicKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertJWTRequest(payload, 0)

	output, err := m.instance.ConvertJWKToPublicKey(m.toString(request.Data()), m.toString(request.KeyId()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertKeyPairToPKCS12(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertKeyPairRequest(payload, 0)

	output, err := m.instance.ConvertKeyPairToPKCS12(m.toString(request.PrivateKey()), m.toString(request.Certificate()), m.toString(request.Password()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPKCS12ToKeyPair(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPKCS12Request(payload, 0)

	output, err := m.instance.ConvertPKCS12ToKeyPair(m.toString(request.Pkcs12()), m.toString(request.Password()))
	if err != nil {
		return m._pkcs12KeyPairResponse(response, output, err)
	}
	return m._pkcs12KeyPairResponse(response, output, nil)
}

func (m instance) convertPrivateKeyToPKCS8(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPrivateKeyRequest(payload, 0)

	output, err := m.instance.ConvertPrivateKeyToPKCS8(m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPrivateKeyToPKCS1(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPrivateKeyRequest(payload, 0)

	output, err := m.instance.ConvertPrivateKeyToPKCS1(m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPrivateKeyToJWK(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPrivateKeyRequest(payload, 0)

	output, err := m.instance.ConvertPrivateKeyToJWK(m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPrivateKeyToPublicKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPrivateKeyRequest(payload, 0)

	output, err := m.instance.ConvertPrivateKeyToPublicKey(m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPublicKeyToPKIX(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPublicKeyRequest(payload, 0)

	output, err := m.instance.ConvertPublicKeyToPKIX(m.toString(request.PublicKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPublicKeyToPKCS1(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPublicKeyRequest(payload, 0)

	output, err := m.instance.ConvertPublicKeyToPKCS1(m.toString(request.PublicKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) convertPublicKeyToJWK(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsConvertPublicKeyRequest(payload, 0)

	output, err := m.instance.ConvertPublicKeyToJWK(m.toString(request.PublicKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) decryptOAEP(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptOAEPRequest(payload, 0)

	output, err := m.instance.DecryptOAEP(m.toString(request.Ciphertext()), m.toString(request.Label()), m.parseHash(request.Hash()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)

}

func (m instance) decryptOAEPBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptOAEPBytesRequest(payload, 0)

	output, err := m.instance.DecryptOAEPBytes(request.CiphertextBytes(), m.toString(request.Label()), m.parseHash(request.Hash()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) decryptPKCS1v15(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptPKCS1v15Request(payload, 0)

	output, err := m.instance.DecryptPKCS1v15(m.toString(request.Ciphertext()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) decryptPKCS1v15Bytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptPKCS1v15BytesRequest(payload, 0)

	output, err := m.instance.DecryptPKCS1v15Bytes(request.CiphertextBytes(), m.toString(request.PrivateKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) decryptPrivateKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsDecryptPrivateKeyRequest(payload, 0)

	output, err := m.instance.DecryptPrivateKey(m.toString(request.PrivateKeyEncrypted()), m.toString(request.Password()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) encryptOAEP(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptOAEPRequest(payload, 0)

	output, err := m.instance.EncryptOAEP(m.toString(request.Message()), m.toString(request.Label()), m.parseHash(request.Hash()), m.toString(request.PublicKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) encryptOAEPBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptOAEPBytesRequest(payload, 0)

	output, err := m.instance.EncryptOAEPBytes(request.MessageBytes(), m.toString(request.Label()), m.parseHash(request.Hash()), m.toString(request.PublicKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) encryptPKCS1v15(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptPKCS1v15Request(payload, 0)

	output, err := m.instance.EncryptPKCS1v15(m.toString(request.Message()), m.toString(request.PublicKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) encryptPKCS1v15Bytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptPKCS1v15BytesRequest(payload, 0)

	output, err := m.instance.EncryptPKCS1v15Bytes(request.MessageBytes(), m.toString(request.PublicKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) encryptPrivateKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsEncryptPrivateKeyRequest(payload, 0)

	output, err := m.instance.EncryptPrivateKey(m.toString(request.PrivateKey()), m.toString(request.Password()), m.parsePEMCipher(request.Cipher()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) generate(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsGenerateRequest(payload, 0)

	output, err := m.instance.Generate(int(request.NBits()))
	if err != nil {
		return m._keyPairResponse(response, output, err)
	}
	return m._keyPairResponse(response, output, nil)
}

func (m instance) hash(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsHashRequest(payload, 0)

	output, err := m.instance.Hash(m.toString(request.Message()), m.parseHash(request.Hash()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) base64(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsBase64Request(payload, 0)

	output, err := m.instance.Base64(m.toString(request.Message()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) metadataPrivateKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsMetadataPrivateKeyRequest(payload, 0)

	output, err := m.instance.MetadataPrivateKey(m.toString(request.PrivateKey()))
	if err != nil {
		return m._privateKeyInfoResponse(response, output, err)
	}
	return m._privateKeyInfoResponse(response, output, nil)
}

func (m instance) metadataPublicKey(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsMetadataPublicKeyRequest(payload, 0)

	output, err := m.instance.MetadataPublicKey(m.toString(request.PublicKey()))
	if err != nil {
		return m._publicKeyInfoResponse(response, output, err)
	}
	return m._publicKeyInfoResponse(response, output, nil)
}

func (m instance) signPKCS1v15(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignPKCS1v15Request(payload, 0)

	output, err := m.instance.SignPKCS1v15(m.toString(request.Message()), m.parseHash(request.Hash()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) signPKCS1v15Bytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignPKCS1v15BytesRequest(payload, 0)

	output, err := m.instance.SignPKCS1v15Bytes(request.MessageBytes(), m.parseHash(request.Hash()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) signPSS(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignPSSRequest(payload, 0)

	output, err := m.instance.SignPSS(m.toString(request.Message()), m.parseHash(request.Hash()), m.parseSaltLength(request.SaltLength()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._stringResponse(response, output, err)
	}
	return m._stringResponse(response, output, nil)
}

func (m instance) signPSSBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsSignPSSBytesRequest(payload, 0)

	output, err := m.instance.SignPSSBytes(request.MessageBytes(), m.parseHash(request.Hash()), m.parseSaltLength(request.SaltLength()), m.toString(request.PrivateKey()))
	if err != nil {
		return m._bytesResponse(response, output, err)
	}
	return m._bytesResponse(response, output, nil)
}

func (m instance) verifyPKCS1v15(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyPKCS1v15Request(payload, 0)

	output, err := m.instance.VerifyPKCS1v15(m.toString(request.Signature()), m.toString(request.Message()), m.parseHash(request.Hash()), m.toString(request.PublicKey()))
	if err != nil {
		return m._boolResponse(response, output, err)
	}
	return m._boolResponse(response, output, nil)
}

func (m instance) verifyPKCS1v15Bytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyPKCS1v15BytesRequest(payload, 0)

	output, err := m.instance.VerifyPKCS1v15Bytes(request.SignatureBytes(), request.MessageBytes(), m.parseHash(request.Hash()), m.toString(request.PublicKey()))
	if err != nil {
		return m._boolResponse(response, output, err)
	}
	return m._boolResponse(response, output, nil)
}

func (m instance) verifyPSS(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyPSSRequest(payload, 0)

	output, err := m.instance.VerifyPSS(m.toString(request.Signature()), m.toString(request.Message()), m.parseHash(request.Hash()), m.parseSaltLength(request.SaltLength()), m.toString(request.PublicKey()))
	if err != nil {
		return m._boolResponse(response, output, err)
	}
	return m._boolResponse(response, output, nil)
}

func (m instance) verifyPSSBytes(payload []byte) []byte {
	response := flatbuffers.NewBuilder(0)
	request := model.GetRootAsVerifyPSSBytesRequest(payload, 0)

	output, err := m.instance.VerifyPSSBytes(request.SignatureBytes(), request.MessageBytes(), m.parseHash(request.Hash()), m.parseSaltLength(request.SaltLength()), m.toString(request.PublicKey()))
	if err != nil {
		return m._boolResponse(response, output, err)
	}
	return m._boolResponse(response, output, nil)
}

func (m instance) parseHash(input model.Hash) string {
	switch input {
	case model.HashMD5:
		return "md5"
	case model.HashSHA1:
		return "sha1"
	case model.HashSHA224:
		return "sha224"
	case model.HashSHA384:
		return "sha384"
	case model.HashSHA512:
		return "sha512"
	case model.HashSHA256:
		fallthrough
	default:
		return "sha256"
	}
}

func (m instance) parseSaltLength(input model.SaltLength) string {
	switch input {
	case model.SaltLengthEQUALS_HASH:
		return "equalsHash"
	case model.SaltLengthAUTO:
		fallthrough
	default:
		return "auto"
	}
}
func (m instance) parsePEMCipher(input model.PEMCipher) string {
	switch input {
	case model.PEMCipherDES:
		return "des"
	case model.PEMCipherD3DES:
		return "3des"
	case model.PEMCipherAES128:
		return "aes128"
	case model.PEMCipherAES192:
		return "aes192"
	case model.PEMCipherAES256:
		fallthrough
	default:
		return "aes256"
	}
}

func (m instance) _pkcs12KeyPairResponse(response *flatbuffers.Builder, output *rsa.PKCS12KeyPair, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.PKCS12KeyPairResponseStart(response)
		model.PKCS12KeyPairResponseAddError(response, outputOffset)
		response.Finish(model.PKCS12KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}

	publicKeyOffset := response.CreateString(output.PublicKey)
	privateKeyOffset := response.CreateString(output.PrivateKey)
	certificateOffset := response.CreateString(output.Certificate)

	model.PKCS12KeyPairStart(response)
	model.PKCS12KeyPairAddPublicKey(response, publicKeyOffset)
	model.PKCS12KeyPairAddPrivateKey(response, privateKeyOffset)
	model.PKCS12KeyPairAddCertificate(response, certificateOffset)
	pkcs12KeyPair := model.PKCS12KeyPairEnd(response)

	model.PKCS12KeyPairResponseStart(response)
	model.PKCS12KeyPairResponseAddOutput(response, pkcs12KeyPair)
	response.Finish(model.PKCS12KeyPairResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _keyPairResponse(response *flatbuffers.Builder, output *rsa.KeyPair, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.KeyPairResponseStart(response)
		model.KeyPairResponseAddError(response, outputOffset)
		response.Finish(model.KeyPairResponseEnd(response))
		return response.FinishedBytes()
	}

	publicKeyOffset := response.CreateString(output.PublicKey)
	privateKeyOffset := response.CreateString(output.PrivateKey)

	model.KeyPairStart(response)
	model.KeyPairAddPublicKey(response, publicKeyOffset)
	model.KeyPairAddPrivateKey(response, privateKeyOffset)
	KeyPair := model.KeyPairEnd(response)

	model.KeyPairResponseStart(response)
	model.KeyPairResponseAddOutput(response, KeyPair)
	response.Finish(model.KeyPairResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _publicKeyInfoResponse(response *flatbuffers.Builder, output *rsa.PublicKeyInfo, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.PublicKeyInfoResponseStart(response)
		model.PublicKeyInfoResponseAddError(response, outputOffset)
		response.Finish(model.PublicKeyInfoResponseEnd(response))
		return response.FinishedBytes()
	}

	model.PublicKeyInfoStart(response)
	model.PublicKeyInfoAddBitLen(response, int64(output.BitLen))
	model.PublicKeyInfoAddSize(response, int64(output.Size))
	model.PublicKeyInfoAddE(response, int64(output.E))
	publicKeyInfo := model.PublicKeyInfoEnd(response)

	model.PublicKeyInfoResponseStart(response)
	model.PublicKeyInfoResponseAddOutput(response, publicKeyInfo)
	response.Finish(model.PublicKeyInfoResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _privateKeyInfoResponse(response *flatbuffers.Builder, output *rsa.PrivateKeyInfo, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.PrivateKeyInfoResponseStart(response)
		model.PrivateKeyInfoResponseAddError(response, outputOffset)
		response.Finish(model.PrivateKeyInfoResponseEnd(response))
		return response.FinishedBytes()
	}

	errorOffset := response.CreateString(output.Error)

	model.PrivateKeyInfoStart(response)
	model.PrivateKeyInfoAddBitLen(response, int64(output.BitLen))
	model.PrivateKeyInfoAddSize(response, int64(output.Size))
	model.PrivateKeyInfoAddError(response, errorOffset)
	privateKeyInfo := model.PrivateKeyInfoEnd(response)

	model.PrivateKeyInfoResponseStart(response)
	model.PrivateKeyInfoResponseAddOutput(response, privateKeyInfo)
	response.Finish(model.PrivateKeyInfoResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _boolResponse(response *flatbuffers.Builder, output bool, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.BoolResponseStart(response)
		model.BoolResponseAddError(response, outputOffset)
		response.Finish(model.BoolResponseEnd(response))
		return response.FinishedBytes()
	}
	model.BoolResponseStart(response)
	model.BoolResponseAddOutput(response, output)
	response.Finish(model.BoolResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _bytesResponse(response *flatbuffers.Builder, output []byte, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.BytesResponseStart(response)
		model.BytesResponseAddError(response, outputOffset)
		response.Finish(model.BytesResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateByteVector(output)
	model.BytesResponseStart(response)
	model.BytesResponseAddOutput(response, outputOffset)
	response.Finish(model.BytesResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) _stringResponse(response *flatbuffers.Builder, output string, err error) []byte {
	if err != nil {
		outputOffset := response.CreateString(err.Error())
		model.StringResponseStart(response)
		model.StringResponseAddError(response, outputOffset)
		response.Finish(model.StringResponseEnd(response))
		return response.FinishedBytes()
	}
	outputOffset := response.CreateString(output)
	model.StringResponseStart(response)
	model.StringResponseAddOutput(response, outputOffset)
	response.Finish(model.StringResponseEnd(response))
	return response.FinishedBytes()
}

func (m instance) toString(input []byte) string {
	if input == nil {
		return ""
	}

	return string(input)
}
