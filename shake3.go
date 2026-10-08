package sha3

/**
 * RawSHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func RawSHAKE128(J []byte, d uint) []byte {
	h_fun := NewKeccak(256)
	return h_fun.keccakWithDomain(J, d, "1111")
}

/**
 * RawSHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func RawSHAKE256(J []byte, d uint) []byte {
	h_fun := NewKeccak(512)
	return h_fun.keccakWithDomain(J, d, "1111")
}

/**
 * SHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func SHAKE128(J []byte, d uint) []byte {
	h_fun := NewKeccak(256)
	return h_fun.keccakWithDomain(J, d, "1111")
}

/**
 * SHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func SHAKE256(J []byte, d uint) []byte {
	h_fun := NewKeccak(512)
	return h_fun.keccakWithDomain(J, d, "1111")
}
