// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type SignPKCS1v15BytesRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsSignPKCS1v15BytesRequest(buf []byte, offset flatbuffers.UOffsetT) *SignPKCS1v15BytesRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &SignPKCS1v15BytesRequest{}
	x.Init(buf, n+offset)
	return x
}

func GetSizePrefixedRootAsSignPKCS1v15BytesRequest(buf []byte, offset flatbuffers.UOffsetT) *SignPKCS1v15BytesRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &SignPKCS1v15BytesRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func (rcv *SignPKCS1v15BytesRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *SignPKCS1v15BytesRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *SignPKCS1v15BytesRequest) Message(j int) byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.GetByte(a + flatbuffers.UOffsetT(j*1))
	}
	return 0
}

func (rcv *SignPKCS1v15BytesRequest) MessageLength() int {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.VectorLen(o)
	}
	return 0
}

func (rcv *SignPKCS1v15BytesRequest) MessageBytes() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *SignPKCS1v15BytesRequest) MutateMessage(j int, n byte) bool {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		a := rcv._tab.Vector(o)
		return rcv._tab.MutateByte(a+flatbuffers.UOffsetT(j*1), n)
	}
	return false
}

func (rcv *SignPKCS1v15BytesRequest) Hash() Hash {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return Hash(rcv._tab.GetInt32(o + rcv._tab.Pos))
	}
	return 0
}

func (rcv *SignPKCS1v15BytesRequest) MutateHash(n Hash) bool {
	return rcv._tab.MutateInt32Slot(6, int32(n))
}

func (rcv *SignPKCS1v15BytesRequest) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(8))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func SignPKCS1v15BytesRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(3)
}
func SignPKCS1v15BytesRequestAddMessage(builder *flatbuffers.Builder, message flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(message), 0)
}
func SignPKCS1v15BytesRequestStartMessageVector(builder *flatbuffers.Builder, numElems int) flatbuffers.UOffsetT {
	return builder.StartVector(1, numElems, 1)
}
func SignPKCS1v15BytesRequestAddHash(builder *flatbuffers.Builder, hash Hash) {
	builder.PrependInt32Slot(1, int32(hash), 0)
}
func SignPKCS1v15BytesRequestAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(2, flatbuffers.UOffsetT(privateKey), 0)
}
func SignPKCS1v15BytesRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}