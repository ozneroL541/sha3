package sha3

// SHA3_224 computes the SHA-3-224 hash of message.
func SHA3_224(message []byte) []byte {
	h_fun := NewKekkak(448)
	return h_fun.kekkak(message, 224)
}

// SHA3_256 computes the SHA-3-256 hash of message.
func SHA3_256(message []byte) []byte {
	h_fun := NewKekkak(512)
	return h_fun.kekkak(message, 256)
}

// SHA3_384 computes the SHA-3-384 hash of message.
func SHA3_384(message []byte) []byte {
	h_fun := NewKekkak(768)
	return h_fun.kekkak(message, 384)
}

// SHA3_512 computes the SHA-3-512 hash of message.
func SHA3_512(message []byte) []byte {
	h_fun := NewKekkak(1024)
	return h_fun.kekkak(message, 512)
}
