package sha3

import (
	"math"
	"strings"
)

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

/**
 * Creates a new Keccak instance.
 * @param c: capacity in bits
 * @return: a new Keccak instance
 */
func NewKeccak(c uint) *Keccak {
	return &Keccak{
		c: c,
	}
}

/**
 * Keccak represents the Keccak hash function with a specified capacity.
 */
type Keccak struct {
	c uint // Capacity in bits
}

/**
 * PermutationFunc defines a generic state transformation function on bit strings.
 */
type PermutationFunc func(string) string

/*
 * PaddingFunc defines a generic padding function.
 */
type PaddingFunc func(x uint, m uint) string

/**
 * Sponge represents SPONGE[f, pad, r] with domain separation support.
 */
type Sponge struct {
	f            PermutationFunc
	pad          PaddingFunc
	r            uint   // Rate in bits
	domainSuffix string // Domain separation bits (e.g., "01" for SHA-3)
}

/**
 * Sponge constructor initializes a new Sponge instance with the specified parameters.
 * @param f: the permutation function to use
 * @param pad: the padding function to use
 * @param r: the rate in bits
 * @param domainSuffix: the domain separation bits
 * @return: a new Sponge instance
 */
func NewSponge(f PermutationFunc, pad PaddingFunc, r uint, domainSuffix string) *Sponge {
	return &Sponge{
		f:            f,
		pad:          pad,
		r:            r,
		domainSuffix: domainSuffix,
	}
}

/**
 * Implements the SPONGE[f, pad, r] construction with domain separation.
 * @param N: input pre-padded byte slice
 * @param d: desired output length in bits
 * @return: output byte slice of length d bits
 */
func (sp *Sponge) sponge(N []byte, d uint) []byte {
	// Step 1: Convert input bytes to bit string and append domain separation bits
	Nbit := bytesToBitString(N) + sp.domainSuffix

	// Step 2 & 3: Pad input using pad101 and break into r-bit blocks
	padded := Nbit
	if sp.pad != nil {
		padded += sp.pad(sp.r, uint(len(Nbit)))
	}
	r := int(sp.r)
	n := len(padded) / r

	b := 1600
	c := b - r
	S := strings.Repeat("0", b)

	// Step 6: Absorbing Phase
	for i := 0; i < n; i++ {
		Pi := padded[i*r : (i+1)*r]
		block := Pi + strings.Repeat("0", c)
		S = xorBitStrings(S, block)
		S = sp.f(S)
	}

	// Steps 7-10: Squeezing Phase
	var Z strings.Builder
	for uint(Z.Len()) < d {
		Z.WriteString(S[:r])
		if uint(Z.Len()) >= d {
			break
		}
		S = sp.f(S)
	}

	// Truncate to d bits and convert back to bytes
	outBits := Z.String()[:d]
	return bitStringToBytes(outBits)
}

/**
 * StateArray represents the 5x5xw state array used in Keccak.
 */
type StateArray struct {
	w int
	A [5][5][]byte
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

/**
 * Step 3.2.1: Theta (θ)
 * @param A: the input StateArray
 * @return: the transformed StateArray after applying theta
 */
func theta(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)

	var C [5][]byte
	for x := 0; x < 5; x++ {
		C[x] = make([]byte, w)
		for z := 0; z < w; z++ {
			C[x][z] = A.A[x][0][z] ^ A.A[x][1][z] ^ A.A[x][2][z] ^ A.A[x][3][z] ^ A.A[x][4][z]
		}
	}

	var D [5][]byte
	for x := 0; x < 5; x++ {
		D[x] = make([]byte, w)
		for z := 0; z < w; z++ {
			D[x][z] = C[(x+4)%5][z] ^ C[(x+1)%5][(z-1+w)%w]
		}
	}

	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			for z := 0; z < w; z++ {
				Aprime.A[x][y][z] = A.A[x][y][z] ^ D[x][z]
			}
		}
	}
	return Aprime
}

/**
 * Step 3.2.2: Rho (ρ)
 * @param A: the input StateArray
 * @return: the transformed StateArray after applying rho
 */
func rho(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)

	for z := 0; z < w; z++ {
		Aprime.A[0][0][z] = A.A[0][0][z]
	}

	x, y := 1, 0
	for t := 0; t <= 23; t++ {
		shift := ((t + 1) * (t + 2) / 2) % w
		for z := 0; z < w; z++ {
			Aprime.A[x][y][z] = A.A[x][y][(z-shift+w)%w]
		}
		x, y = y, (2*x+3*y)%5
	}
	return Aprime
}

/**
 * Step 3.2.3: Pi (π)
 * @param A: the input StateArray
 * @return: the transformed StateArray after applying pi
 */
func pi(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			for z := 0; z < w; z++ {
				Aprime.A[x][y][z] = A.A[(x+3*y)%5][x][z]
			}
		}
	}
	return Aprime
}

/**
 * Step 3.2.4: Chi (χ)
 * @param A: the input StateArray
 * @return: the transformed StateArray after applying chi
 */
func chi(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			for z := 0; z < w; z++ {
				bit1 := A.A[(x+1)%5][y][z] ^ 1
				bit2 := A.A[(x+2)%5][y][z]
				Aprime.A[x][y][z] = A.A[x][y][z] ^ (bit1 & bit2)
			}
		}
	}
	return Aprime
}

/**
 * Step 3.2.5: Algorithm 5 - Linear feedback shift register rc(t)
 * @param t: the round number
 * @return: the round constant
 */
func rc(t int) byte {
	if t%255 == 0 {
		return 1
	}
	R := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}
	for i := 1; i <= t%255; i++ {
		for k := 8; k > 0; k-- {
			R[k] = R[k-1]
		}
		R[0] = 0

		R[0] ^= R[8]
		R[4] ^= R[8]
		R[5] ^= R[8]
		R[6] ^= R[8]
	}
	return R[0]
}

/**
 * Step 3.2.5: Algorithm 6 - Iota (ι)
 * @param A: the input StateArray
 * @param ir: the round index
 * @param l: the lane size
 * @return: the transformed StateArray after applying iota
 */
func iotaStep(A *StateArray, ir int, l int) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	for x := 0; x < 5; x++ {
		for y := 0; y < 5; y++ {
			copy(Aprime.A[x][y], A.A[x][y])
		}
	}

	RC := make([]byte, w)
	for j := 0; j <= l; j++ {
		idx := (1 << j) - 1
		if idx < w {
			RC[idx] = rc(j + 7*ir)
		}
	}

	for z := 0; z < w; z++ {
		Aprime.A[0][0][z] ^= RC[z]
	}
	return Aprime
}

/**
 * Step 3.2.6: Round function Rnd
 * @param A: the input StateArray
 * @param ir: the round index
 * @param l: the lane size
 * @return: the transformed StateArray after applying the round function
 */
func Rnd(A *StateArray, ir int, l int) *StateArray {
	return iotaStep(chi(pi(rho(theta(A)))), ir, l)
}

/**
 * pad10*1
 * @param x: the rate in bits
 * @param m: the length of the message in bits
 * @return: the padding string
 */
func pad101(x uint, m uint) string {
	if x == 0 {
		panic("x must be greater than 0")
	}
	j := (x - ((m + 2) % x)) % x
	return "1" + strings.Repeat("0", int(j)) + "1"
}

/**
 * KekkaP
 * Represents the KECCAK-p[b, nr] permutation
 * with a specified bit length and number of rounds.
 */
type KekkaP struct {
	b  int
	nr int
}

/**
 * Creates a new KekkaP instance with
 * the specified bit length and number of rounds.
 * @param b: bit length of the internal state
 * @param nr: number of rounds
 * @return: a new KekkaP instance
 */
func NewKekkaP(b int, nr int) *KekkaP {
	return &KekkaP{
		b:  b,
		nr: nr,
	}
}

/**
 * Algorithm 7: KECCAK-p[b, nr](S)
 * @param S: the input string
 * @return: the output string
 */
func (k *KekkaP) algorithm7(S string) string {
	w := k.b / 25
	l := int(math.Log2(float64(w)))

	A := stringToStateArray(S, w)

	startRound := 12 + 2*l - k.nr
	endRound := 12 + 2*l - 1
	for ir := startRound; ir <= endRound; ir++ {
		A = Rnd(A, ir, l)
	}

	return stateArrayToString(A)
}

/**
 * Keccak represents the KECCAK hash function
 * with a specified capacity.
 */
type Keccak struct {
	c int
}

/**
 * Creates a new Keccak instance with the specified capacity.
 * @param c: capacity in bits
 * @return: a new Keccak instance
 */
func NewKeccak(c int) *Keccak {
	return &Keccak{
		c: c,
	}
}

/**
 * Implements the KECCAK hash function as per FIPS 202 Sec 4.2.
 * @param N: input pre-padded byte slice
 * @param d: desired output length in bits
 * @return: output byte slice of length d bits
 */
func (k *Keccak) keccak(N []byte, d uint) []byte {
	kekkap := NewKekkaP(1600, 24)
	sponge := NewSponge(kekkap.algorithm7, pad101, uint(1600-k.c), "01")
	return sponge.sponge(N, d)
}
