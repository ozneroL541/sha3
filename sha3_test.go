package sha3

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

const KAT_DIR = "KAT/"
const BYTE_TEST_VECTORS_DIR = "sha-3bytetestvectors/"
const SHAKE_BYTE_TEST_VECTORS_DIR = "shakebytetestvectors/"
const FILENAME_SUFFIX = ".rsp"

var byteTestVectors []string = []string{
	"ShortMsg",
	"LongMsg",
	"Monte",
}

/**
 * runKAT reads a KAT file and executes the provided hash function on each message, comparing the result to the expected hash.
 * If the hash function is not implemented (returns nil), the test is skipped.
 * If the actual hash does not match the expected hash, an error is reported.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param filepath string - The path to the KAT file.
 * @param hashFunc func([]byte) []byte - The hash function to be tested, which takes a byte slice and returns a byte slice.
 */
func runKAT(t *testing.T, filepath string, hashFunc func([]byte) []byte) {
	// Open the KAT file for reading
	file, err := os.Open(filepath)
	if err != nil {
		t.Fatalf("Failed to open KAT file %s: %v", filepath, err)
	}
	defer file.Close()

	// Create a scanner to read the file line by line
	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		t.Fatalf("Failed to read KAT file %s: %v", filepath, err)
		return
	}
	var msg []byte        /** Message to be hashed */
	var expectedMD []byte /** Expected message digest (hash) */

	// For each line in the KAT file
	for scanner.Scan() {
		// Trim whitespace
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments and go to
		// Msg line
		if strings.HasPrefix(line, "Msg = ") {
			// Extract the message from the line
			msgHex := strings.TrimPrefix(line, "Msg = ")
			// Handle the special case for 0-length messages
			if msgHex == "00" {
				// Handle 0-length messages (NIST uses "00" but Len = 0)
				msg = []byte{}
			} else {
				// Decode the hex string into a byte slice
				msg, _ = hex.DecodeString(msgHex)
			}
			// If the line starts with "MD = ", it contains the expected hash
		} else if strings.HasPrefix(line, "MD = ") {
			// Extract the expected hash from the line
			mdHex := strings.TrimPrefix(line, "MD = ")
			// Decode the hex string into a byte slice
			expectedMD, _ = hex.DecodeString(mdHex)
			// Execute the target hash function
			actualMD := hashFunc(msg)
			// If the hash function is not implemented (returns nil), skip the test
			if actualMD == nil {
				t.Skip("Implementation missing, skipping verification")
				return
			}
			// Compare the actual hash to the expected hash
			if !bytes.Equal(actualMD, expectedMD) {
				t.Errorf(
					"Hash mismatch!\n"+
						"File: %s\n"+
						"Expected: %x\nGot:      %x", filepath, expectedMD, actualMD,
				)
			}
		}
	}
}

/**
 * runMonteKAT parses a NIST SHA-3 Monte Carlo test file (.rsp) and executes 1,000 inner
 * hash loop iterations for each outer count iteration, matching results against the expected MD.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param filepath string - The path to the Monte Carlo KAT file.
 * @param hashFunc func([]byte) []byte - The hash function to be tested.
 */
func runMonteKAT(t *testing.T, filepath string, hashFunc func([]byte) []byte) {
	file, err := os.Open(filepath)
	if err != nil {
		t.Fatalf("Failed to open KAT file %s: %v", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if err := scanner.Err(); err != nil {
		t.Fatalf("Failed to read KAT file %s: %v", filepath, err)
		return
	}

	var seed []byte
	var expectedMD []byte

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "Seed = ") {
			seedHex := strings.TrimPrefix(line, "Seed = ")
			seed, _ = hex.DecodeString(seedHex)
		} else if strings.HasPrefix(line, "MD = ") {
			mdHex := strings.TrimPrefix(line, "MD = ")
			expectedMD, _ = hex.DecodeString(mdHex)

			// Per NIST CAVP SHA-3 Monte Carlo specification:
			// Execute 1,000 hash iterations per outer count loop
			for i := 0; i < 1000; i++ {
				seed = hashFunc(seed)
				if seed == nil {
					t.Skip("Implementation missing, skipping verification")
					return
				}
			}

			// Verify the 1,000th iteration digest against the test vector expected MD
			if !bytes.Equal(seed, expectedMD) {
				t.Errorf(
					"Monte Carlo Hash mismatch!\n"+
						"File: %s\n"+
						"Expected: %x\nGot:      %x", filepath, expectedMD, seed,
				)
			}
		}
	}
}

/**
 * testSHA3Parametrical runs the KAT tests for a given hash function.
 * It reads the corresponding KAT file and executes the test for each message and expected hash.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param filename string - The name of the KAT file (without directory).
 * @param hashFunc func([]byte) []byte - The hash function to be tested, which takes a byte slice and returns a byte slice.
 */
func testSHA3Parametrical(t *testing.T, filename string, hashFunc func([]byte) []byte) {
	filepath := KAT_DIR + filename
	if strings.Contains(filename, "Monte") {
		runMonteKAT(t, filepath, hashFunc)
	} else {
		runKAT(t, filepath, hashFunc)
	}
}

/**
 * testSHA3_bytetestvectors runs the byte test vectors for a given hash function.
 * It reads the corresponding test vector file and executes the test for each message and expected hash.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param filename string - The name of the byte test vector file (without directory and suffix).
 * @param hashFunc func([]byte) []byte - The hash function to be tested, which takes a byte slice and returns a byte slice.
 */
func testSHA3_bytetestvectors(t *testing.T, filename string, hashFunc func([]byte) []byte) {
	filepath := BYTE_TEST_VECTORS_DIR + filename + FILENAME_SUFFIX
	testSHA3Parametrical(t, filepath, hashFunc)
}

func runSHAKEKAT(t *testing.T, filepath string, hashFunc func([]byte, uint) []byte) {
	file, err := os.Open(filepath)
	if err != nil {
		t.Fatalf("Failed to open KAT file %s: %v", filepath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var msg []byte
	var outputLen uint

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.Contains(line, "Outputlen = "):
			outputLenValue := strings.TrimSpace(strings.Trim(line[strings.Index(line, "Outputlen = ")+len("Outputlen = "):], "[]"))
			parsedOutputLen, err := strconv.ParseUint(outputLenValue, 10, 32)
			if err != nil {
				t.Fatalf("Invalid output length %q in KAT file %s: %v", outputLenValue, filepath, err)
			}
			outputLen = uint(parsedOutputLen)
		case strings.HasPrefix(line, "Msg = "):
			msgHex := strings.TrimPrefix(line, "Msg = ")
			if msgHex == "00" {
				msg = []byte{}
			} else {
				msg, err = hex.DecodeString(msgHex)
				if err != nil {
					t.Fatalf("Invalid message %q in KAT file %s: %v", msgHex, filepath, err)
				}
			}
		case strings.HasPrefix(line, "Output = "):
			outputHex := strings.TrimPrefix(line, "Output = ")
			expectedOutput, err := hex.DecodeString(outputHex)
			if err != nil {
				t.Fatalf("Invalid output %q in KAT file %s: %v", outputHex, filepath, err)
			}

			actualOutput := msg
			iterations := 1
			if strings.Contains(filepath, "Monte") {
				iterations = 1000
			}
			for i := 0; i < iterations; i++ {
				actualOutput = hashFunc(actualOutput, outputLen)
				if actualOutput == nil {
					t.Skip("Implementation missing, skipping verification")
					return
				}
			}
			if !bytes.Equal(actualOutput, expectedOutput) {
				t.Errorf(
					"SHAKE mismatch!\n"+
						"File: %s\nExpected: %x\nGot:      %x",
					filepath, expectedOutput, actualOutput,
				)
			}
			if iterations > 1 {
				msg = actualOutput
			}
		}
	}

	if err := scanner.Err(); err != nil {
		t.Fatalf("Failed to read KAT file %s: %v", filepath, err)
	}
}

func testSHAKE_bytetestvectors(t *testing.T, filename string, hashFunc func([]byte, uint) []byte) {
	filepath := KAT_DIR + SHAKE_BYTE_TEST_VECTORS_DIR + filename + FILENAME_SUFFIX
	runSHAKEKAT(t, filepath, hashFunc)
}

func testSHAKE_all_bytetestvectors(t *testing.T, name string, hashFunc func([]byte, uint) []byte) {
	for _, vector := range []string{"ShortMsg", "LongMsg", "VariableOut"} {
		testSHAKE_bytetestvectors(t, name+vector, hashFunc)
	}
}

/**
 * testSHA3_all_bytetestvectors runs the byte test vectors for a given hash function.
 * It iterates over a predefined list of byte test vector filenames and executes the test for each.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param name string - The base name of the hash function being tested (e.g., "SHA3_224").
 * @param hashFunc func([]byte) []byte - The hash function to be tested, which takes a byte slice and returns a byte slice.
 */
func testSHA3_all_bytetestvectors(t *testing.T, name string, hashFunc func([]byte) []byte) {
	for _, vector := range byteTestVectors {
		testSHA3_bytetestvectors(t, name+vector, hashFunc)
	}
}

func TestSHA3_224(t *testing.T) {
	const sha = "SHA3_224"
	testSHA3_all_bytetestvectors(t, sha, SHA3_224)
}

func TestSHA3_256(t *testing.T) {
	const sha = "SHA3_256"
	testSHA3_all_bytetestvectors(t, sha, SHA3_256)
}

func TestSHA3_384(t *testing.T) {
	const sha = "SHA3_384"
	testSHA3_all_bytetestvectors(t, sha, SHA3_384)
}

func TestSHA3_512(t *testing.T) {
	const sha = "SHA3_512"
	testSHA3_all_bytetestvectors(t, sha, SHA3_512)
}

func TestSHAKE128(t *testing.T) {
	const shake = "SHAKE128"
	testSHAKE_all_bytetestvectors(t, shake, SHAKE128)
}

func TestSHAKE256(t *testing.T) {
	const shake = "SHAKE256"
	testSHAKE_all_bytetestvectors(t, shake, SHAKE256)
}
