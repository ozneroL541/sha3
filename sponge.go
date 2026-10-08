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
	// 1. Let P=N || pad(r, len(N)).
	P := bytesToBitString(N) + sp.domainSuffix
	if sp.pad != nil {
		P += sp.pad(sp.r, uint(len(P)))
	}
	// 2. Let n=len(P)/r.
	n := uint(len(P)) / sp.r
	// 3. Let c=b-r.
	b := uint(1600)
	c := b - sp.r
	S := strings.Repeat("0", int(b))
	// 4. Let P0, … , Pn-1 be the unique sequence of strings of
	// length r such that P = P0 || … || Pn-1.
	for i := range n {
		Pi := P[i*sp.r : (i+1)*sp.r]
		block := Pi + strings.Repeat("0", int(c))
		// 5. Let S=0^b.
		// 6. For i from 0 to n-1, let S=f (S ⊕ (Pi || 0^c)).
		S = xorBitStrings(S, block)
		S = sp.f(S)
	}
	// 7. Let Z be the empty string.
	var Z strings.Builder
	// 8. Let Z=Z || Truncr(S).
	for uint(Z.Len()) < d {
		Z.WriteString(S[:sp.r])
		// 9. If d≤|Z|, then return Trunc d (Z); else continue.
		if uint(Z.Len()) >= d {
			break
		}
		S = sp.f(S)
	}
	outBits := Z.String()[:d]
	// 10. Let S=f(S), and continue with Step 8.
	return bitStringToBytes(outBits)
}
