// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type DecryptPrivateKeyRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsDecryptPrivateKeyRequest(buf []byte, offset flatbuffers.UOffsetT) *DecryptPrivateKeyRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &DecryptPrivateKeyRequest{}
	x.Init(buf, n+offset)
	return x
}

func (rcv *DecryptPrivateKeyRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *DecryptPrivateKeyRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *DecryptPrivateKeyRequest) PrivateKeyEncrypted() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *DecryptPrivateKeyRequest) Password() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func DecryptPrivateKeyRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(2)
}
func DecryptPrivateKeyRequestAddPrivateKeyEncrypted(builder *flatbuffers.Builder, privateKeyEncrypted flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(privateKeyEncrypted), 0)
}
func DecryptPrivateKeyRequestAddPassword(builder *flatbuffers.Builder, password flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(password), 0)
}
func DecryptPrivateKeyRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}