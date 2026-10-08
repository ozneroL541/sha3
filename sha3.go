package sha3

/**
 * SHA3_224 computes the SHA-3-224 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-224 hash of the input message
 */
func SHA3_224(message []byte) []byte {
	h_fun := NewKeccak(448)
	M01 := concat(message, "01")
	return h_fun.keccak(M01, 224)
}

/**
 * SHA3_256 computes the SHA-3-256 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-256 hash of the input message
 */
func SHA3_256(message []byte) []byte {
	h_fun := NewKeccak(512)
	M01 := concat(message, "01")
	return h_fun.keccak(M01, 256)
}

/**
 * SHA3_384 computes the SHA-3-384 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-384 hash of the input message
 */
func SHA3_384(message []byte) []byte {
	h_fun := NewKeccak(768)
	M01 := concat(message, "01")
	return h_fun.keccak(M01, 384)
}

/**
 * SHA3_512 computes the SHA-3-512 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-512 hash of the input message
 */
func SHA3_512(message []byte) []byte {
	h_fun := NewKeccak(1024)
	M01 := concat(message, "01")
	return h_fun.keccak(M01, 512)
}
