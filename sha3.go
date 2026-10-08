package sha3

/**
 * SHA3_224 computes the SHA-3-224 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-224 hash of the input message
 */
func SHA3_224(message []byte) []byte {
	return newKeccak(448, "01").keccak(message, 224)
}

/**
 * SHA3_256 computes the SHA-3-256 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-256 hash of the input message
 */
func SHA3_256(message []byte) []byte {
	return newKeccak(512, "01").keccak(message, 256)
}

/**
 * SHA3_384 computes the SHA-3-384 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-384 hash of the input message
 */
func SHA3_384(message []byte) []byte {
	return newKeccak(768, "01").keccak(message, 384)
}

/**
 * SHA3_512 computes the SHA-3-512 hash of message.
 * @param message: input message to hash
 * @return: SHA-3-512 hash of the input message
 */
func SHA3_512(message []byte) []byte {
	return newKeccak(1024, "01").keccak(message, 512)
}
