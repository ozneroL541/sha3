package sha3

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
 * @return: the transformed StateArray after applying IotaAlg
 */
func IotaAlg(A *StateArray, ir int) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	// 1. For all triples (x, y,z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let A′[x, y,z] = A[x, y,z]
	for x := range 5 {
		for y := range 5 {
			copy(Aprime.A[x][y], A.A[x][y])
		}
	}
	// 2. Let RC=0^w.
	RC := make([]byte, w)
	// 3. For j from 0 to l, let RC[2j-1]=rc(j+7ir).
	l := A.getL()
	for j := 0; j <= l; j++ {
		idx := (1 << j) - 1
		if idx < w {
			RC[idx] = rc(j + 7*ir)
		}
	}
	// 4. For all z such that 0≤z<w, let A′[0, 0,z]=A′[0, 0,z] ⊕ RC[z].
	for z := range w {
		Aprime.A[0][0][z] ^= RC[z]
	}
	// 5. Return A'.
	return Aprime
}
