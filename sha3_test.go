package sha3

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

const KAT_DIR = "KAT/"
const BYTE_TEST_VECTORS_DIR = "sha-3bytetestvectors/"
const FILENAME_SUFFIX = ".rsp"

var byteTestVectors []string = []string{
	"ShortMsg",
	"LongMsg",
	//"Monte",
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
		defer file.Close()
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
 * testSHA3Parametrical runs the KAT tests for a given hash function.
 * It reads the corresponding KAT file and executes the test for each message and expected hash.
 * @param t *testing.T - The testing object used for reporting errors and skipping tests.
 * @param filename string - The name of the KAT file (without directory).
 * @param hashFunc func([]byte) []byte - The hash function to be tested, which takes a byte slice and returns a byte slice.
 */
func testSHA3Parametrical(t *testing.T, filename string, hashFunc func([]byte) []byte) {
	filepath := KAT_DIR + filename
	runKAT(t, filepath, hashFunc)
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
