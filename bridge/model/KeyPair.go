// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type KeyPair struct {
	_tab flatbuffers.Table
}

func GetRootAsKeyPair(buf []byte, offset flatbuffers.UOffsetT) *KeyPair {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &KeyPair{}
	x.Init(buf, n+offset)
	return x
}

func FinishKeyPairBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsKeyPair(buf []byte, offset flatbuffers.UOffsetT) *KeyPair {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &KeyPair{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedKeyPairBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *KeyPair) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *KeyPair) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *KeyPair) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func (rcv *KeyPair) PublicKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func KeyPairStart(builder *flatbuffers.Builder) {
	builder.StartObject(2)
}
func KeyPairAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(privateKey), 0)
}
func KeyPairAddPublicKey(builder *flatbuffers.Builder, publicKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(publicKey), 0)
}
func KeyPairEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
