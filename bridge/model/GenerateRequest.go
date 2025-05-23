// Code generated by the FlatBuffers compiler. DO NOT EDIT.

package model

import (
	flatbuffers "github.com/google/flatbuffers/go"
)

type GenerateRequest struct {
	_tab flatbuffers.Table
}

func GetRootAsGenerateRequest(buf []byte, offset flatbuffers.UOffsetT) *GenerateRequest {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &GenerateRequest{}
	x.Init(buf, n+offset)
	return x
}

func FinishGenerateRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.Finish(offset)
}

func GetSizePrefixedRootAsGenerateRequest(buf []byte, offset flatbuffers.UOffsetT) *GenerateRequest {
	n := flatbuffers.GetUOffsetT(buf[offset+flatbuffers.SizeUint32:])
	x := &GenerateRequest{}
	x.Init(buf, n+offset+flatbuffers.SizeUint32)
	return x
}

func FinishSizePrefixedGenerateRequestBuffer(builder *flatbuffers.Builder, offset flatbuffers.UOffsetT) {
	builder.FinishSizePrefixed(offset)
}

func (rcv *GenerateRequest) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *GenerateRequest) Table() flatbuffers.Table {
	return rcv._tab
}

func (rcv *GenerateRequest) NBits() int32 {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.GetInt32(o + rcv._tab.Pos)
	}
	return 0
}

func (rcv *GenerateRequest) MutateNBits(n int32) bool {
	return rcv._tab.MutateInt32Slot(4, n)
}

func GenerateRequestStart(builder *flatbuffers.Builder) {
	builder.StartObject(1)
}
func GenerateRequestAddNBits(builder *flatbuffers.Builder, nBits int32) {
	builder.PrependInt32Slot(0, nBits, 0)
}
func GenerateRequestEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT {
	return builder.EndObject()
}
