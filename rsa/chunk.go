package rsa

type chunkCallback = func(i, to int) ([]byte, error)

func processChunk(size, offset int, callback chunkCallback) ([]byte, error) {
	var output []byte
	for i := 0; i < size; i += offset {
		to := i + offset
		if to > size {
			to = size
		}
		chunk, err := callback(i, to)
		if err != nil {
			return nil, err
		}
		output = append(output, chunk...)
	}
	return output, nil
}
