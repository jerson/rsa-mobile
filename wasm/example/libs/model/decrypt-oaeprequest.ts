// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { Hash } from '../model/hash.js';


export class DecryptOAEPRequest {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):DecryptOAEPRequest {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsDecryptOAEPRequest(bb:flatbuffers.ByteBuffer, obj?:DecryptOAEPRequest):DecryptOAEPRequest {
  return (obj || new DecryptOAEPRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsDecryptOAEPRequest(bb:flatbuffers.ByteBuffer, obj?:DecryptOAEPRequest):DecryptOAEPRequest {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new DecryptOAEPRequest()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

ciphertext():string|null
ciphertext(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
ciphertext(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
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

static startDecryptOAEPRequest(builder:flatbuffers.Builder) {
  builder.startObject(4);
}

static addCiphertext(builder:flatbuffers.Builder, ciphertextOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, ciphertextOffset, 0);
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

static endDecryptOAEPRequest(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createDecryptOAEPRequest(builder:flatbuffers.Builder, ciphertextOffset:flatbuffers.Offset, labelOffset:flatbuffers.Offset, hash:Hash, privateKeyOffset:flatbuffers.Offset):flatbuffers.Offset {
  DecryptOAEPRequest.startDecryptOAEPRequest(builder);
  DecryptOAEPRequest.addCiphertext(builder, ciphertextOffset);
  DecryptOAEPRequest.addLabel(builder, labelOffset);
  DecryptOAEPRequest.addHash(builder, hash);
  DecryptOAEPRequest.addPrivateKey(builder, privateKeyOffset);
  return DecryptOAEPRequest.endDecryptOAEPRequest(builder);
}
}