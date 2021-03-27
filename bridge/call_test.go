package rsaBridge

import (
	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/jerson/rsa-mobile/bridge/model"
	"testing"
)

func TestCall(t *testing.T) {

	b := flatbuffers.NewBuilder(0)

	model.GenerateRequestStart(b)
	model.GenerateRequestAddNBits(b, 2048)
	b.Finish(model.GenerateRequestEnd(b))

	data, err := Call("generate", b.FinishedBytes())
	if err != nil {
		t.Fatal(err)
		return
	}
	response := model.GetRootAsKeyPairResponse(data, 0)
	errOutput := response.Error()
	if errOutput != nil {
		t.Log(string(errOutput))
		return
	}
	keyPairOutput := response.Output(nil)
	t.Log(string(keyPairOutput.PrivateKey()))
	t.Log(string(keyPairOutput.PublicKey()))
}
