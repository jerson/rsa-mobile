// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type PKCS12KeyPairResponse struct {
	_tab flatbuffers.Table
}

func GetRootAsPKCS12KeyPairResponse(buf []byte, offset flatbuffers.UOffsetT) *PKCS12KeyPairResponse {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &PKCS12KeyPairResponse{}
	x.Init(buf, n+offset)
	return x
}

func FinishPKCS12KeyPairResponseBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsPKCS12KeyPairResponse(buf []byte, offset flatbuffers.UOffsetT) *PKCS12KeyPairResponse {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &PKCS12KeyPairResponse{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedPKCS12KeyPairResponseBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *PKCS12KeyPairResponse) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *PKCS12KeyPairResponse) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *PKCS12KeyPairResponse) Output(obj *PKCS12KeyPair) *PKCS12KeyPair {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		x := rcv._tab.Indirect(o + rcv._tab.Pos)
		if obj == nil {
			obj = new(PKCS12KeyPair)
		}
		obj.Init(rcv._tab.Bytes, x)
		return obj
	}
	return nil
}

func (rcv *PKCS12KeyPairResponse) Error() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func PKCS12KeyPairResponseStart(builder *flatbuffers.Builder) {
	builder.StartObject(2)
}
func PKCS12KeyPairResponseAddOutput(builder *flatbuffers.Builder, output flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(output), 0)
}
func PKCS12KeyPairResponseAddError(builder *flatbuffers.Builder, error flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(1, flatbuffers.UOffsetT(error), 0)
}
func PKCS12KeyPairResponseEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
