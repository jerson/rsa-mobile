// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type SignPSSRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsSignPSSRequest(buf []byte, offset flatbuffers.UOffsetT) *SignPSSRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &SignPSSRequest{}
	x.Init(buf, n+offset)
	return x
}

func GetSizePrefixedRootAsSignPSSRequest(buf []byte, offset flatbuffers.UOffsetT) *SignPSSRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &SignPSSRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func (rcv *SignPSSRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *SignPSSRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *SignPSSRequest) Message() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *SignPSSRequest) Hash() Hash {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return Hash(rcv._tab.GetInt32(o + rcv._tab.Pos))
	}
	return 0
}

func (rcv *SignPSSRequest) MutateHash(n Hash) bool {
	return rcv._tab.MutateInt32Slot(6, int32(n))
}

func (rcv *SignPSSRequest) SaltLength() SaltLength {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(8))
	if o != 0 {
		return SaltLength(rcv._tab.GetInt32(o + rcv._tab.Pos))
	}
	return 0
}

func (rcv *SignPSSRequest) MutateSaltLength(n SaltLength) bool {
	return rcv._tab.MutateInt32Slot(8, int32(n))
}

func (rcv *SignPSSRequest) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(10))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func SignPSSRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(4)
}
func SignPSSRequestAddMessage(builder *flatbuffers.Builder, message flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(message), 0)
}
func SignPSSRequestAddHash(builder *flatbuffers.Builder, hash Hash) {
	builder.PrependInt32Slot(1, int32(hash), 0)
}
func SignPSSRequestAddSaltLength(builder *flatbuffers.Builder, saltLength SaltLength) {
	builder.PrependInt32Slot(2, int32(saltLength), 0)
}
func SignPSSRequestAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(3, flatbuffers.UOffsetT(privateKey), 0)
}
func SignPSSRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}