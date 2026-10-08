package sha3

import (
	"math"
	"strings"
)

/**
 * PermutationFunc defines a generic state transformation function on bit strings.
 */
type PermutationFunc func(string) string

/*
 * PaddingFunc defines a generic padding function.
 */
type PaddingFunc func(x uint, m uint) string

/**
 * Step 3.3: Round function of a Keccak-p permutation
 * @param A: StateArray
 * @param ir: round index
 * @param l: the lane size
 * @return: the transformed StateArray after applying the round function
 */
func Rnd(A *StateArray, ir int) *StateArray {
	return IotaAlg(chi(pi(rho(theta(A)))), ir)
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
 * KeccakP
 * Represents the KECCAK-p[b, nr] permutation
 * with a specified bit length and number of rounds.
 */
type KeccakP struct {
	b  int /** Length of string S */
	nr int /** Iterations of Rnd */
}

/**
 * Creates a new KeccakP instance with
 * the specified bit length and number of rounds.
 * @param b: bit length of the internal state
 * @param nr: number of rounds
 * @return: a new KeccakP instance
 */
func NewKeccakP(b int, nr int) *KeccakP {
	return &KeccakP{
		b:  b,
		nr: nr,
	}
}

/**
 * Algorithm 7: KECCAK-p[b, nr](S)
 * @param S: the input string
 * @return: S' of length b
 */
func (k *KeccakP) algorithm7(S string) string {
	w := k.b / 25 /** Lane size in bits */
	// 1. Convert S to a StateArray A, as described in Section 3.1.2.
	A := stringToStateArray(S, w)

	// 2. For ir from 12+2l - nr to 12+2l -1, let A=Rnd(A, ir).
	l := int(math.Log2(float64(w))) /** Lane size in bits */
	start := 12 + 2*l - k.nr
	end := 12 + 2*l - 1
	for ir := start; ir <= end; ir++ {
		A = Rnd(A, ir)
	}

	return stateArrayToString(A)
}

/**
 * Keccak represents the KECCAK hash function
 * with a specified capacity.
 */
type Keccak struct {
	c int /** Capacity in bits */
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
	keccakp := NewKeccakP(1600, 24)
	sponge := NewSponge(keccakp.algorithm7, pad101, uint(1600-k.c), "01")
	return sponge.sponge(N, d)
}
