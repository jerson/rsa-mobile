// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { Hash } from '../model/hash.js';


export class DecryptOAEPBytesRequest {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):DecryptOAEPBytesRequest {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsDecryptOAEPBytesRequest(bb:flatbuffers.ByteBuffer, obj?:DecryptOAEPBytesRequest):DecryptOAEPBytesRequest {
  return (obj || new DecryptOAEPBytesRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsDecryptOAEPBytesRequest(bb:flatbuffers.ByteBuffer, obj?:DecryptOAEPBytesRequest):DecryptOAEPBytesRequest {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new DecryptOAEPBytesRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

ciphertext(index: number):number|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.readUint8(this.bb!.__vector(this.bb_pos + offset) + index) : 0;
}

ciphertextLength():number {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

ciphertextArray():Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? new Uint8Array(this.bb!.bytes().buffer, this.bb!.bytes().byteOffset + this.bb!.__vector(this.bb_pos + offset), this.bb!.__vector_len(this.bb_pos + offset)) : null;
}

label():string|null
label(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
label(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

hash():Hash {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.readInt32(this.bb_pos + offset) : Hash.MD5;
}

mutate_hash(value:Hash):boolean {
  const offset = this.bb!.__offset(this.bb_pos, 8);

  if (offset === 0) {
    return false;
  }

  this.bb!.writeInt32(this.bb_pos + offset, value);
  return true;
}

privateKey():string|null
privateKey(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
privateKey(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

static startDecryptOAEPBytesRequest(builder:flatbuffers.Builder) {
  builder.startObject(4);
}

static addCiphertext(builder:flatbuffers.Builder, ciphertextOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, ciphertextOffset, 0);
}

static createCiphertextVector(builder:flatbuffers.Builder, data:number[]|Uint8Array):flatbuffers.Offset {
  builder.startVector(1, data.length, 1);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]!);
  }
  return builder.endVector();
}

static startCiphertextVector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(1, numElems, 1);
}

static addLabel(builder:flatbuffers.Builder, labelOffset:flatbuffers.Offset) {
  builder.addFieldOffset(1, labelOffset, 0);
}

static addHash(builder:flatbuffers.Builder, hash:Hash) {
  builder.addFieldInt32(2, hash, Hash.MD5);
}

static addPrivateKey(builder:flatbuffers.Builder, privateKeyOffset:flatbuffers.Offset) {
  builder.addFieldOffset(3, privateKeyOffset, 0);
}

static endDecryptOAEPBytesRequest(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createDecryptOAEPBytesRequest(builder:flatbuffers.Builder, ciphertextOffset:flatbuffers.Offset, labelOffset:flatbuffers.Offset, hash:Hash, privateKeyOffset:flatbuffers.Offset):flatbuffers.Offset {
  DecryptOAEPBytesRequest.startDecryptOAEPBytesRequest(builder);
  DecryptOAEPBytesRequest.addCiphertext(builder, ciphertextOffset);
  DecryptOAEPBytesRequest.addLabel(builder, labelOffset);
  DecryptOAEPBytesRequest.addHash(builder, hash);
  DecryptOAEPBytesRequest.addPrivateKey(builder, privateKeyOffset);
  return DecryptOAEPBytesRequest.endDecryptOAEPBytesRequest(builder);
}
}
