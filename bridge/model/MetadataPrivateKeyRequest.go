// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type MetadataPrivateKeyRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsMetadataPrivateKeyRequest(buf []byte, offset flatbuffers.UOffsetT) *MetadataPrivateKeyRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &MetadataPrivateKeyRequest{}
	x.Init(buf, n+offset)
	return x
}

func GetSizePrefixedRootAsMetadataPrivateKeyRequest(buf []byte, offset flatbuffers.UOffsetT) *MetadataPrivateKeyRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &MetadataPrivateKeyRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func (rcv *MetadataPrivateKeyRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *MetadataPrivateKeyRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *MetadataPrivateKeyRequest) PrivateKey() []byte {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.ByteVector(o + rcv._tab.Pos)
	}
	return nil
}

func MetadataPrivateKeyRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func MetadataPrivateKeyRequestAddPrivateKey(builder *flatbuffers.Builder, privateKey flatbuffers.UOffsetT) {
	builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(privateKey), 0)
}
func MetadataPrivateKeyRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}