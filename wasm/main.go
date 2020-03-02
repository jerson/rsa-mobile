// +build js,wasm

package main

import (
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

func DecryptOAEP(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptOAEP(i[0].String(), i[1].String(), i[2].String(), i[3].String(), i[4].String())
	})
}

func DecryptPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.DecryptPKCS1v15(i[0].String(), i[1].String(), i[2].String())
	})
}

func EncryptOAEP(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptOAEP(i[0].String(), i[1].String(), i[2].String(), i[3].String(), i[4].String())
	})
}

func EncryptPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.EncryptPKCS1v15(i[0].String(), i[1].String(), i[2].String())
	})

}

func Generate(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		resultKeyPair, err := instance.Generate(i[0].Int())
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{
			"publicKey":  resultKeyPair.PublicKey,
			"privateKey": resultKeyPair.PrivateKey,
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
		return instance.SignPKCS1v15(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func SignPSS(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.SignPSS(i[0].String(), i[1].String(), i[2].String(), i[3].String())
	})
}

func VerifyPKCS1v15(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.VerifyPKCS1v15(i[0].String(), i[1].String(), i[2].String(), i[3].String(), i[4].String())
	})
}

func VerifyPSS(this js.Value, i []js.Value) interface{} {
	return Promise(i, func() (result interface{}, err error) {
		return instance.VerifyPSS(i[0].String(), i[1].String(), i[2].String(), i[3].String(), i[4].String())
	})
}

func registerCallbacks() {
	js.Global().Set("RSADecryptOAEP", js.FuncOf(DecryptOAEP))
	js.Global().Set("RSADecryptPKCS1v15", js.FuncOf(DecryptPKCS1v15))
	js.Global().Set("RSAEncryptOAEP", js.FuncOf(EncryptOAEP))
	js.Global().Set("RSAEncryptPKCS1v15", js.FuncOf(EncryptPKCS1v15))
	js.Global().Set("RSAGenerate", js.FuncOf(Generate))
	js.Global().Set("RSAHash", js.FuncOf(Hash))
	js.Global().Set("RSASignPKCS1v15", js.FuncOf(SignPKCS1v15))
	js.Global().Set("RSASignPSS", js.FuncOf(SignPSS))
	js.Global().Set("RSAVerifyPKCS1v15", js.FuncOf(VerifyPKCS1v15))
	js.Global().Set("RSAVerifyPSS", js.FuncOf(VerifyPSS))
	js.Global().Set("RSABase64", js.FuncOf(Base64))
}

func main() {
	c := make(chan bool, 0)
	registerCallbacks()
	<-c
}
