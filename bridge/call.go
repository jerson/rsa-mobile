package rsaBridge

import (
	"fmt"
	"github.com/golang/protobuf/proto"
	"github.com/jerson/rsa-mobile/bridge/model"

	//"github.com/jerson/rsa-mobile/bridge/model"
	"github.com/jerson/rsa-mobile/rsa"
)

// Call ...
func Call(name string, payload []byte) ([]byte, error) {

	instance := NewInstance()
	var output proto.Message
	switch name {
	case "decrypt":
		output = instance.decrypt(payload)
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

func (m instance) decrypt(payload []byte) proto.Message {
	response := &model.StringResponse{}
	/*request := &model.DecryptRequest{}
	err := proto.Unmarshal(payload, request)
	if err != nil {
		response.Error = err.Error()
		return response
	}

	output, err := m.instance.Decrypt(request.Message, request.PrivateKey, request.Passphrase, m.parseKeyOptions(request.Options))
	if err != nil {
		response.Error = err.Error()
		return response
	}
	response.Output = output*/
	return response
}
