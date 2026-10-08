package sha3

/**
 * RawSHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func RawSHAKE128(J []byte, d uint) []byte {
	h_fun := NewKeccak(256)
	M11 := concat(J, "1111")
	return h_fun.keccak(M11, d)
}

/**
 * RawSHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func RawSHAKE256(J []byte, d uint) []byte {
	h_fun := NewKeccak(512)
	M11 := concat(J, "1111")
	return h_fun.keccak(M11, d)
}

/**
 * SHAKE128 computes the SHAKE128 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE128 hash of the input J with output length d bits
 */
func SHAKE128(J []byte, d uint) []byte {
	h_fun := NewKeccak(256)
	M11 := concat(J, "1111")
	return h_fun.keccak(M11, d)
}

/**
 * SHAKE256 computes the SHAKE256 hash of input J with output length d bits.
 * @param J: input byte slice
 * @param d: desired output length in bits
 * @return: SHAKE256 hash of the input J with output length d bits
 */
func SHAKE256(J []byte, d uint) []byte {
	h_fun := NewKeccak(512)
	M11 := concat(J, "1111")
	return h_fun.keccak(M11, d)
}
