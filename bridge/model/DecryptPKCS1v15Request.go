// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type DecryptPKCS1v15Request struct {
	_tab flatbuffers.Table
}

func GetRootAsDecryptPKCS1v15Request(buf []byte, offset flatbuffers.UOffsetT) *DecryptPKCS1v15Request {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &DecryptPKCS1v15Request{}
	x.Init(buf, n+offset)
	return x
}

func FinishDecryptPKCS1v15RequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsDecryptPKCS1v15Request(buf []byte, offset flatbuffers.UOffsetT) *DecryptPKCS1v15Request {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &DecryptPKCS1v15Request{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedDecryptPKCS1v15RequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *DecryptPKCS1v15Request) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *DecryptPKCS1v15Request) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *DecryptPKCS1v15Request) Ciphertext() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *DecryptPKCS1v15Request) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func DecryptPKCS1v15RequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(2)
}
func DecryptPKCS1v15RequestAddCiphertext(builder *flatbuffers.Builder, ciphertext flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(ciphertext), 0)
}
func DecryptPKCS1v15RequestAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(privateKey), 0)
}
func DecryptPKCS1v15RequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
