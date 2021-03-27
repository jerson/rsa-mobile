const myWorker = new Worker('worker.js');

const sample = async () => {
    const builder = new flatbuffers.Builder(0);

    model.GenerateRequest.startGenerateRequest(builder);
    model.GenerateRequest.addNBits(builder, 2048);
    const offset = model.GenerateRequest.endGenerateRequest(builder);
    builder.finish(offset);

    const bytes = builder.asUint8Array()

    console.log('request', bytes);
    const rawResponse = await send('generate', bytes)

    const responseBuffer = new flatbuffers.ByteBuffer(rawResponse);
    const response = model.KeyPairResponse.getRootAsKeyPairResponse(responseBuffer, null)
    if (response.error()) {
        throw new Error(response.error())
    }
    const output =  response.output()
    console.log('privateKey', output.privateKey());
    console.log('publicKey', output.publicKey());
}

let counter = 0;
const send = (name, request) => {
    counter++;
    const id = counter.toString()

    return new Promise((resolve, reject) => {

        const callbackError = (e) => {
            reject('callbackError: ' + e)
        }
        const callbackMessageError = (e) => {
            reject('callbackMessageError: ' + e)
        }
        const callback = (e) => {
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