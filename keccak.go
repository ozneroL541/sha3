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
 * 3.3: Round function of a Keccak-p permutation
 * @param A: StateArray
 * @param ir: round index
 * @param l: the lane size
 * @return: the transformed StateArray after applying the round function
 */
func Rnd(A *StateArray, ir int) *StateArray {
	return IotaAlg(chi(pi(rho(theta(A)))), ir)
}

/**
 * 5.1 pad10*1
 * Algorithm 9: pad10*1(x, m)
 * @param x: positive integer
 * @param m: non-negative integer
 * @return: string P such that m + len(P) is a positive multiple of x.
 */
func pad101(x uint, m uint) string {
	if x == 0 {
		panic("x must be greater than 0")
	}
	// 1. Let j = (- m - 2) mod x.
	j := (x - ((m + 2) % x)) % x
	// 2. Return P = 1 || 0^j || 1.
	P := "1" + strings.Repeat("0", int(j)) + "1"
	return P
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
	// 3. Convert A into a string S′ of length b, as described in Sec. 3.1.3.
	S_prime := stateArrayToString(A)
	// 4. Return S′.
	return S_prime
}

/**
 * Keccak represents the KECCAK hash function
 * with a specified capacity.
 */
type Keccak struct {
	c      int    /** Capacity in bits */
	domain string /** Domain separation suffix */
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

func newKeccak(c int, domain string) *Keccak {
	return &Keccak{
		c:      c,
		domain: domain,
	}
}

/**
 * 5.2 Keccak[c]
 * @param N: input pre-padded byte slice
 * @param d: desired output length in bits
 * @return: output byte slice of length d bits
 */
func (k *Keccak) keccak(N []byte, d uint) []byte {
	keccakp := NewKeccakP(1600, 24)
	padding := func(x uint, m uint) string {
		return k.domain + pad101(x, m+uint(len(k.domain)))
	}
	sponge := NewSponge(keccakp.algorithm7, padding, uint(1600-k.c))
	return sponge.sponge(N, d)
}

/**
 * Returns the lane size in bits for the Keccak instance.
 * @return: lane size in bits
 */
func getLaneSize() int {
	keccakp := NewKeccakP(1600, 24)
	return keccakp.b / 25 /** Lane size in bits = 64 */
}
