// +build js,wasm

package main

import (
	"encoding/base64"
	"errors"
	"syscall/js"

	"github.com/jerson/rsa-mobile/rsa"
)

var instance = rsa.NewFastRSA()

func Promise(i []js.Value, fn func() (result interface{}, err error)) interface{} {

	if len(i) < 1 {
		println(errors.New("error: required at least one argument").Error())
		return nil
	}
	callback := i[len(i)-1:][0]
	if callback.Type() != js.TypeFunction {
		println(errors.New("error: last argument should be a callback(err,result)").Error())
		return nil
	}
	go func() {
		result, err := fn()
		if err != nil {
			callback.Invoke(err.Error(), js.Null())
			return
		}
		callback.Invoke(js.Null(), js.ValueOf(result))
	}()

	return nil
}

func ConvertJWKToPrivateKey(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertJWKToPrivateKey(i[0].String(), i[1].String())
	})
}

func ConvertJWKToPublicKey(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertJWKToPublicKey(i[0].String(), i[1].String())
	})
}

func ConvertKeyPairToPKCS12(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertKeyPairToPKCS12(i[0].String(), i[1].String(), i[2].String())
	})

}

func ConvertPKCS12ToKeyPair(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		resultKeyPair, err := instance.ConvertPKCS12ToKeyPair(i[0].String(), i[1].String())
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"privateKey":  resultKeyPair.PrivateKey,
			"publicKey":   resultKeyPair.PublicKey,
			"certificate": resultKeyPair.Certificate,
		}, err
	})
}

func ConvertPrivateKeyToPKCS8(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPrivateKeyToPKCS8(i[0].String())
	})
}

func ConvertPrivateKeyToPKCS1(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPrivateKeyToPKCS1(i[0].String())
	})
}

func ConvertPrivateKeyToJWK(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPrivateKeyToJWK(i[0].String())
	})
}

func ConvertPrivateKeyToPublicKey(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPrivateKeyToPublicKey(i[0].String())
	})
}

func ConvertPublicKeyToPKIX(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPublicKeyToPKIX(i[0].String())
	})
}

func ConvertPublicKeyToPKCS1(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPublicKeyToPKCS1(i[0].String())
	})
}

func ConvertPublicKeyToJWK(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.ConvertPublicKeyToJWK(i[0].String())
	})
}

func DecryptPrivateKey(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptPrivateKey(i[0].String(), i[1].String())
	})
}

func EncryptPrivateKey(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptPrivateKey(i[0].String(), i[1].String(), i[2].String())
	})
}

func DecryptOAEP(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptOAEP(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func DecryptOAEPBytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.DecryptOAEPBytes(data, i[1].String(), i[2].String(), i[3].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func DecryptPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptPKCS1v15(i[0].String(), i[1].String())
	})
}

func DecryptPKCS1v15Bytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.DecryptPKCS1v15Bytes(data, i[1].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func EncryptOAEP(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptOAEP(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func EncryptOAEPBytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.EncryptOAEPBytes(data, i[1].String(), i[2].String(), i[3].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func EncryptPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptPKCS1v15(i[0].String(), i[1].String())
	})

}

func EncryptPKCS1v15Bytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.EncryptPKCS1v15Bytes(data, i[1].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})

}

func Generate(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		resultKeyPair, err := instance.Generate(i[0].Int())
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"privateKey": resultKeyPair.PrivateKey,
			"publicKey":  resultKeyPair.PublicKey,
		}, err
	})
}

func Hash(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Hash(i[0].String(), i[1].String())
	})
}

func Base64(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.Base64(i[0].String())
	})
}

func SignPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.SignPKCS1v15(i[0].String(), i[1].String(), i[2].String())
	})
}

func SignPKCS1v15Bytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.SignPKCS1v15Bytes(data, i[1].String(), i[2].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func SignPSS(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.SignPSS(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func SignPSSBytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		output, err := instance.SignPSSBytes(data, i[1].String(), i[2].String(), i[3].String())
		if err != nil {
			return result, err
		}
		return base64.StdEncoding.EncodeToString(output), err
	})
}

func VerifyPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.VerifyPKCS1v15(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func VerifyPKCS1v15Bytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		return instance.VerifyPKCS1v15Bytes(data, []byte(i[1].String()), i[2].String(), i[3].String())
	})
}

func VerifyPSS(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.VerifyPSS(i[0].String(), i[1].String(), i[2].String(), i[3].String(), i[4].String())
	})
}

func VerifyPSSBytes(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		data, err := base64.StdEncoding.DecodeString(i[0].String())
		if err != nil {
			return nil, err
		}
		return instance.VerifyPSSBytes(data, []byte(i[1].String()), i[2].String(), i[3].String(), i[4].String())
	})
}

func registerCallbacks() {
	js.Global().Set("RSAConvertJWKToPrivateKey", js.FuncOf(ConvertJWKToPrivateKey))
	js.Global().Set("RSAConvertJWKToPublicKey", js.FuncOf(ConvertJWKToPublicKey))
	js.Global().Set("RSAConvertKeyPairToPKCS12", js.FuncOf(ConvertKeyPairToPKCS12))
	js.Global().Set("RSAConvertPKCS12ToKeyPair", js.FuncOf(ConvertPKCS12ToKeyPair))
	js.Global().Set("RSAConvertPrivateKeyToPKCS8", js.FuncOf(ConvertPrivateKeyToPKCS8))
	js.Global().Set("RSAConvertPrivateKeyToPKCS1", js.FuncOf(ConvertPrivateKeyToPKCS1))
	js.Global().Set("RSAConvertPrivateKeyToJWK", js.FuncOf(ConvertPrivateKeyToJWK))
	js.Global().Set("RSAConvertPrivateKeyToPublicKey", js.FuncOf(ConvertPrivateKeyToPublicKey))
	js.Global().Set("RSAConvertPublicKeyToPKIX", js.FuncOf(ConvertPublicKeyToPKIX))
	js.Global().Set("RSAConvertPublicKeyToPKCS1", js.FuncOf(ConvertPublicKeyToPKCS1))
	js.Global().Set("RSAConvertPublicKeyToJWK", js.FuncOf(ConvertPublicKeyToJWK))
	js.Global().Set("RSADecryptPrivateKey", js.FuncOf(DecryptPrivateKey))
	js.Global().Set("RSAEncryptPrivateKey", js.FuncOf(EncryptPrivateKey))
	js.Global().Set("RSADecryptOAEP", js.FuncOf(DecryptOAEP))
	js.Global().Set("RSADecryptOAEPBytes", js.FuncOf(DecryptOAEPBytes))
	js.Global().Set("RSADecryptPKCS1v15", js.FuncOf(DecryptPKCS1v15))
	js.Global().Set("RSADecryptPKCS1v15Bytes", js.FuncOf(DecryptPKCS1v15Bytes))
	js.Global().Set("RSAEncryptOAEP", js.FuncOf(EncryptOAEP))
	js.Global().Set("RSAEncryptOAEPBytes", js.FuncOf(EncryptOAEPBytes))
	js.Global().Set("RSAEncryptPKCS1v15", js.FuncOf(EncryptPKCS1v15))
	js.Global().Set("RSAEncryptPKCS1v15Bytes", js.FuncOf(EncryptPKCS1v15Bytes))
	js.Global().Set("RSAGenerate", js.FuncOf(Generate))
	js.Global().Set("RSAHash", js.FuncOf(Hash))
	js.Global().Set("RSASignPKCS1v15", js.FuncOf(SignPKCS1v15))
	js.Global().Set("RSASignPKCS1v15Bytes", js.FuncOf(SignPKCS1v15Bytes))
	js.Global().Set("RSASignPSS", js.FuncOf(SignPSS))
	js.Global().Set("RSASignPSSBytes", js.FuncOf(SignPSSBytes))
	js.Global().Set("RSAVerifyPKCS1v15", js.FuncOf(VerifyPKCS1v15))
	js.Global().Set("RSAVerifyPKCS1v15Bytes", js.FuncOf(VerifyPKCS1v15Bytes))
	js.Global().Set("RSAVerifyPSS", js.FuncOf(VerifyPSS))
	js.Global().Set("RSAVerifyPSSBytes", js.FuncOf(VerifyPSSBytes))
	js.Global().Set("RSABase64", js.FuncOf(Base64))
}

func main() {
	c := make(chan bool, 0)
	registerCallbacks()
	<-c
}
