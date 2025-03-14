// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type VerifyPKCS1v15Request struct {
	_tab flatbuffers.Table
}

func GetRootAsVerifyPKCS1v15Request(buf []byte, offset flatbuffers.UOffsetT) *VerifyPKCS1v15Request {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &VerifyPKCS1v15Request{}
	x.Init(buf, n+offset)
	return x
}

func FinishVerifyPKCS1v15RequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsVerifyPKCS1v15Request(buf []byte, offset flatbuffers.UOffsetT) *VerifyPKCS1v15Request {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &VerifyPKCS1v15Request{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedVerifyPKCS1v15RequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *VerifyPKCS1v15Request) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *VerifyPKCS1v15Request) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *VerifyPKCS1v15Request) Signature() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *VerifyPKCS1v15Request) Message() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *VerifyPKCS1v15Request) Hash() Hash {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(8))
	if o != 0 {
		return Hash(rcv._tab.GetInt32(o + rcv._tab.Pos))
	}
	return 0
}

func (rcv *VerifyPKCS1v15Request) MutateHash(n Hash) bool {
	return rcv._tab.MutateInt32Slot(8, int32(n))
}

func (rcv *VerifyPKCS1v15Request) PublicKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(10))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func VerifyPKCS1v15RequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(4)
}
func VerifyPKCS1v15RequestAddSignature(builder *flatbuffers.Builder, signature flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(signature), 0)
}
func VerifyPKCS1v15RequestAddMessage(builder *flatbuffers.Builder, message flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(message), 0)
}
func VerifyPKCS1v15RequestAddHash(builder *flatbuffers.Builder, hash Hash) {
	builder.PrependInt32Slot(2, int32(hash), 0)
}
func VerifyPKCS1v15RequestAddPublicKey(builder *flatbuffers.Builder, publicKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(3, flatbuffers.UOffsetT(publicKey), 0)
}
func VerifyPKCS1v15RequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
