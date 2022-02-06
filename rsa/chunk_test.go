package rsa

func getBigInputMessage() string {
	output := ""
	for i := 0; i < 10000; i++ {
		output += inputMessage
	}

	return output
}
