// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type ConvertPrivateKeyRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsConvertPrivateKeyRequest(buf []byte, offset flatbuffers.UOffsetT) *ConvertPrivateKeyRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &ConvertPrivateKeyRequest{}
	x.Init(buf, n+offset)
	return x
}

func FinishConvertPrivateKeyRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsConvertPrivateKeyRequest(buf []byte, offset flatbuffers.UOffsetT) *ConvertPrivateKeyRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &ConvertPrivateKeyRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedConvertPrivateKeyRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *ConvertPrivateKeyRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *ConvertPrivateKeyRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *ConvertPrivateKeyRequest) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func ConvertPrivateKeyRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func ConvertPrivateKeyRequestAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(privateKey), 0)
}
func ConvertPrivateKeyRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
