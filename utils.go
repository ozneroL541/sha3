package sha3

import "strings"

/**
 * Helper functions for bit string and byte slice conversions
 * @param data: byte slice to convert to bit string
 * @return: bit string representation of the byte slice
 */
func bytesToBitString(data []byte) string {
	var sb strings.Builder
	sb.Grow(len(data) * 8)
	for _, b := range data {
		for j := 0; j < 8; j++ {
			if (b>>j)&1 == 1 {
				sb.WriteByte('1')
			} else {
				sb.WriteByte('0')
			}
		}
	}
	return sb.String()
}

/**
 * Converts a bit string back to a byte slice.
 * @param s: bit string to convert
 * @return: byte slice representation of the bit string
 */
func bitStringToBytes(s string) []byte {
	numBytes := (len(s) + 7) / 8
	res := make([]byte, numBytes)
	for i := 0; i < len(s); i++ {
		if s[i] == '1' {
			res[i/8] |= (1 << (i % 8))
		}
	}
	return res
}

/**
 * xorBitStrings computes the bitwise XOR of two equal-length bit strings.
 * @param s1: first bit string
 * @param s2: second bit string
 * @return: the bitwise XOR of the two bit strings
 */
func xorBitStrings(s1, s2 string) string {
	if len(s1) != len(s2) {
		panic("bit strings must be of equal length for XOR")
	}
	var sb strings.Builder
	sb.Grow(len(s1))
	for i := 0; i < len(s1); i++ {
		if s1[i] == s2[i] {
			sb.WriteByte('0')
		} else {
			sb.WriteByte('1')
		}
	}
	return sb.String()
}
