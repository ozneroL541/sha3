package sha3

import (
	"math"
	"strings"
)

/**
 * StateArray represents the 5x5xw
 * state array used in Keccak.
 */
type StateArray struct {
	w int
	A [5][5][]byte
}

/**
 * For a Keccak-p permutation,
 * the binary logarithm of the lane size, i.e.,log2(w).
 * @return: the lane size in bits
 */
func (sa *StateArray) getL() int {
	return int(math.Log2(float64(sa.w)))
}

/**
 * Creates a new StateArray with the specified lane size w.
 * @param w: lane size in bits
 * @return: a new StateArray instance
 */
func NewStateArray(w int) *StateArray {
	sa := &StateArray{w: w}
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			sa.A[x][y] = make([]byte, w)
		}
	}
	return sa
}

/**
 * Converts a bit string to a StateArray.
 * @param S: the bit string
 * @param w: lane size in bits
 * @return: a new StateArray instance
 */
func stringToStateArray(S string, w int) *StateArray {
	sa := NewStateArray(w)
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			for z := 0; z < w; z++ {
				idx := w*(5*y+x) + z
				sa.A[x][y][z] = S[idx] - '0'
			}
		}
	}
	return sa
}

/**
 * Converts a StateArray to a bit string.
 * @param sa: the StateArray
 * @return: the bit string
 */
func stateArrayToString(sa *StateArray) string {
	var sb strings.Builder
	sb.Grow(5 * 5 * sa.w)
	for j := 0; j < 5; j++ {
		for i := 0; i < 5; i++ {
			for z := 0; z < sa.w; z++ {
				if sa.A[i][j][z] == 1 {
					sb.WriteByte('1')
				} else {
					sb.WriteByte('0')
				}
			}
		}
	}
	return sb.String()
}
