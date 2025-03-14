// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

export class BytesResponse {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):BytesResponse {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsBytesResponse(bb:flatbuffers.ByteBuffer, obj?:BytesResponse):BytesResponse {
  return (obj || new BytesResponse()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsBytesResponse(bb:flatbuffers.ByteBuffer, obj?:BytesResponse):BytesResponse {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new BytesResponse()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

output(index: number):number|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.readUint8(this.bb!.__vector(this.bb_pos + offset) + index) : 0;
}

outputLength():number {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

outputArray():Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? new Uint8Array(this.bb!.bytes().buffer, this.bb!.bytes().byteOffset + this.bb!.__vector(this.bb_pos + offset), this.bb!.__vector_len(this.bb_pos + offset)) : null;
}

error():string|null
error(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
error(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

static startBytesResponse(builder:flatbuffers.Builder) {
  builder.startObject(2);
}

static addOutput(builder:flatbuffers.Builder, outputOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, outputOffset, 0);
}

static createOutputVector(builder:flatbuffers.Builder, data:number[]|Uint8Array):flatbuffers.Offset {
  builder.startVector(1, data.length, 1);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]!);
  }
  return builder.endVector();
}

static startOutputVector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(1, numElems, 1);
}

static addError(builder:flatbuffers.Builder, errorOffset:flatbuffers.Offset) {
  builder.addFieldOffset(1, errorOffset, 0);
}

static endBytesResponse(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createBytesResponse(builder:flatbuffers.Builder, outputOffset:flatbuffers.Offset, errorOffset:flatbuffers.Offset):flatbuffers.Offset {
  BytesResponse.startBytesResponse(builder);
  BytesResponse.addOutput(builder, outputOffset);
  BytesResponse.addError(builder, errorOffset);
  return BytesResponse.endBytesResponse(builder);
}
}
