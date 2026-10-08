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
 * Sponge constructor initializes a new Sponge instance
 * with the specified parameters.
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
 * 4 Sponge
 * Algorithm 8: SPONGE[f, pad, r](N, d)
 * @param N: string
 * @param d: nonnegative integer
 * @return: string Z such that len(Z) = d
 */
func (sp *Sponge) sponge(N []byte, d uint) []byte {
	if d == 0 {
		panic("d must be a nonnegative integer")
	}

	// Algorithm 8, Step 1: encode N as bits, append the domain-separation
	// suffix, and apply the selected padding function.
	Nbit := bytesToBitString(N) + sp.domainSuffix
	padded := Nbit
	if sp.pad != nil {
		padded += sp.pad(sp.r, uint(len(Nbit)))
	}

	// Algorithm 8, Steps 2 and 4: determine the number of r-bit input
	// blocks and keep the padded message available for block extraction.
	r := int(sp.r)
	n := len(padded) / r

	// Algorithm 8, Steps 3 and 5: the state has b=1600 bits, so c is the
	// capacity and the initial state is the all-zero string 0^b.
	b := 1600
	c := b - r
	S := strings.Repeat("0", b)

	// Algorithm 8, Step 6 (absorbing phase): append 0^c to each r-bit
	// message block, XOR it into the state, and apply the permutation f.
	for i := 0; i < n; i++ {
		Pi := padded[i*r : (i+1)*r]
		block := Pi + strings.Repeat("0", c)
		S = xorBitStrings(S, block)
		S = sp.f(S)
	}

	// Algorithm 8, Steps 7-10 (squeezing phase): concatenate r-bit
	// prefixes of the state, permuting between output blocks as needed.
	var Z strings.Builder
	for uint(Z.Len()) < d {
		Z.WriteString(S[:r])
		if uint(Z.Len()) >= d {
			break
		}
		S = sp.f(S)
	}

	// Algorithm 8, Step 9: truncate the generated stream to exactly d bits
	// before converting the result back to bytes for the Go API.
	outBits := Z.String()[:d]
	return bitStringToBytes(outBits)
}
