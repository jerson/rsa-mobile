import * as flatbuffers from 'flatbuffers';
import {GenerateRequest, KeyPairResponse} from "../libs/model";

export const GenerateSample = async () => {

    const builder = new flatbuffers.Builder(0);

    GenerateRequest.startGenerateRequest(builder);
    GenerateRequest.addNBits(builder, 2048);
    const offset = GenerateRequest.endGenerateRequest(builder);
    builder.finish(offset);

    const bytes = builder.asUint8Array()

    console.log('request', bytes);
    const rawResponse = await sendToWorker('generate', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = KeyPairResponse.getRootAsKeyPairResponse(responseBuffer)
    if (response.error()) {
        throw new Error(response.error()!)
    }
    const output = response.output()
    console.log('privateKey', output!.privateKey());
    console.log('publicKey', output!.publicKey());
}

let counter = 0;
const sendToWorker = (name: string, request: Uint8Array) => {
    const myWorker = new Worker('worker.js');
    counter++;
    const id = counter.toString()

    return new Promise<Uint8Array>((resolve, reject) => {

        const callbackError = (e: any) => {
            reject('callbackError: ' + e)
        }
        const callbackMessageError = (e: any) => {
            reject('callbackMessageError: ' + e)
        }
        const callback = (e: any) => {
            const data = e.data || {}
            if (id !== data.id) {
                // if not same if we should not reject
                return
            }
            myWorker.removeEventListener('message', callback)
            const {error, response} = data;
            if (error) {
                reject(error)
            }
            resolve(response);
        }

        myWorker.addEventListener('message', callback)
        myWorker.addEventListener('error', callbackError)
        myWorker.addEventListener("messageerror", callbackMessageError)
        myWorker.postMessage({id, name, request});
    })
}