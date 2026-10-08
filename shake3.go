package sha3

/**
 * RawSHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func RawSHAKE128(J []byte, d uint) []byte {
	return newKeccak(256, "1111").keccak(J, d)
}

/**
 * RawSHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func RawSHAKE256(J []byte, d uint) []byte {
	return newKeccak(512, "1111").keccak(J, d)
}

/**
 * SHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func SHAKE128(J []byte, d uint) []byte {
	return newKeccak(256, "1111").keccak(J, d)
}

/**
 * SHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func SHAKE256(J []byte, d uint) []byte {
	return newKeccak(512, "1111").keccak(J, d)
}

/**
 * SHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits and the final state
 */
func SHAKE256WithState(J []byte, d uint) ([]byte, *StateArray) {
	return newKeccak(512, "1111").keccakWithState(J, d)
}
