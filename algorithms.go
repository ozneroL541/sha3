package sha3

/**
 * 3.2.1: Theta (θ)
 * Algorithm 1: θ(A)
 * @param A: state array
 * @return: state array A'
 */
func theta(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	var C [5][]byte
	// 1. For all pairs (x,z) such that 0≤x<5 and 0≤z<w
	for x := range 5 {
		C[x] = make([]byte, w)
		for z := range w {
			// let C[x,z]=A[x, 0,z] ⊕ A[x, 1,z] ⊕ A[x, 2,z] ⊕ A[x, 3,z] ⊕ A[x, 4,z].
			C[x][z] = A.A[x][0][z] ^ A.A[x][1][z] ^ A.A[x][2][z] ^ A.A[x][3][z] ^ A.A[x][4][z]
		}
	}
	var D [5][]byte
	// 2. For all pairs (x, z) such that 0≤x<5 and 0≤z<w
	for x := range 5 {
		D[x] = make([]byte, w)
		for z := range w {
			// D[x,z]=C[(x-1) mod 5, z] ⊕ C[(x+1) mod 5, (z-1) mod w]
			D[x][z] = C[(x+4)%5][z] ^ C[(x+1)%5][(z-1+w)%w]
		}
	}
	// 3. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
	for x := range 5 {
		for y := range 5 {
			for z := range w {
				// A'[x, y,z] = A[x, y,z] ⊕ D[x,z]
				Aprime.A[x][y][z] = A.A[x][y][z] ^ D[x][z]
			}
		}
	}
	return Aprime
}

/**
 * 3.2.2: Rho (ρ)
 * Algorithm 2: ρ(A)
 * @param A: state array
 * @return: state array A'
 */
func rho(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	// 1. For all z such that 0≤z<w
	for z := range w {
		// let A′ [0, 0,z] = A[0, 0,z]
		Aprime.A[0][0][z] = A.A[0][0][z]
	}
	// 2. Let (x, y) = (1, 0).
	x, y := 1, 0
	// 3. For t from 0 to 23:
	for t := 0; t <= 23; t++ {
		t_things := ((t + 1) * (t + 2)) / 2
		// a. for all z such that 0≤z<w
		for z := range w {
			// let A′[x, y,z] = A[x, y, (z-(t+1)(t+2)/2) mod w];
			offset := (z - t_things) % w
			if offset < 0 {
				offset += w
			}
			Aprime.A[x][y][z] = A.A[x][y][offset]
		}
		// b. let (x, y) = (y, (2x+3y) mod 5).
		x, y = y, (2*x+3*y)%5
	}
	// 4. Return A′
	return Aprime
}

/**
 * 3.2.3: Pi (π)
 * Algorithm 3: π(A)
 * @param A: state array
 * @return: state array A'
 */
func pi(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	// 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
	for x := range 5 {
		for y := range 5 {
			for z := range w {
				// A′[x, y, z]=A[(x + 3y) mod 5, x, z].
				Aprime.A[x][y][z] = A.A[(x+3*y)%5][x][z]
			}
		}
	}
	// 2. Return A′.
	return Aprime
}

/**
 * 3.2.4: Chi (χ)
 * Algorithm 4: χ(A)
 * @param A: the input StateArray
 * @return: the transformed StateArray after applying chi
 */
func chi(A *StateArray) *StateArray {
	w := A.w
	Aprime := NewStateArray(w)
	// 1. For all triples (x, y, z) such that 0≤x<5, 0≤y<5, and 0≤z<w, let
	for x := range 5 {
		for y := range 5 {
			for z := range w {
				// A′[x, y,z] = A[x, y,z] ⊕ ((A[(x+1) mod 5, y, z] ⊕ 1) ⋅ A[(x+2) mod 5, y, z]).
				sa1 := A.A[(x+1)%5][y][z] ^ 1
				sa2 := A.A[(x+2)%5][y][z]
				Aprime.A[x][y][z] = A.A[x][y][z] ^ (sa1 & sa2)
			}
		}
	}
	// 2. Return A′.
	return Aprime
}

/**
 * 3.2.5: Linear Feedback Shift Register
 * Algorithm 5: rc(t)
 * @param t: integer
 * @return: bit rc(t)
 */
func rc(t int) byte {
	// 1. If t mod 255 = 0, return 1.
	if t%255 == 0 {
		return 1
	}
	// 2. Let R = 10000000.
	R := []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}
	// 3. For i from 1 to t mod 255, let:
	for i := 1; i <= t%255; i++ {
		// a. R = 0 || R;
		for k := 8; k > 0; k-- {
			R[k] = R[k-1]
		}
		R[0] = 0
		// b. R[0] = R[0] ⊕ R[8];
		R[0] ^= R[8]
		// c. R[4] = R[4] ⊕ R[8];
		R[4] ^= R[8]
		// d. R[5] = R[5] ⊕ R[8];
		R[5] ^= R[8]
		// e. R[6] = R[6] ⊕ R[8];
		R[6] ^= R[8]
		// f. R =Trunc8[R].
	}
	// Equivalent
	//R := byte(1)
	//for i := 0; i < t%255; i++ {
	//	if R&0x80 != 0 {
	//		R = (R << 1) ^ 0x71
	//	} else {
	//		R <<= 1
	//	}
	//}
	//R &= 1

	// 4. Return R[0].
	return R[0]
}

/**
 * 3.2.5: Algorithm 6 - Iota (ι)
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
