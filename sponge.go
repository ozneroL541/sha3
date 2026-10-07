package sha3

import "strings"

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
