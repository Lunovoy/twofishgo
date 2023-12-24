package main

import (
	// "crypto/rand"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/bits"
	"os"
	"strconv"
)

type Mode int

const (
	Encrypt Mode = 0
	Decrypt Mode = 1
)

var ftable = []uint8{0xa3, 0xd7, 0x09, 0x83, 0xf8, 0x48, 0xf6, 0xf4, 0xb3, 0x21, 0x15, 0x78, 0x99, 0xb1, 0xaf, 0xf9,
	0xe7, 0x2d, 0x4d, 0x8a, 0xce, 0x4c, 0xca, 0x2e, 0x52, 0x95, 0xd9, 0x1e, 0x4e, 0x38, 0x44, 0x28,
	0x0a, 0xdf, 0x02, 0xa0, 0x17, 0xf1, 0x60, 0x68, 0x12, 0xb7, 0x7a, 0xc3, 0xe9, 0xfa, 0x3d, 0x53,
	0x96, 0x84, 0x6b, 0xba, 0xf2, 0x63, 0x9a, 0x19, 0x7c, 0xae, 0xe5, 0xf5, 0xf7, 0x16, 0x6a, 0xa2,
	0x39, 0xb6, 0x7b, 0x0f, 0xc1, 0x93, 0x81, 0x1b, 0xee, 0xb4, 0x1a, 0xea, 0xd0, 0x91, 0x2f, 0xb8,
	0x55, 0xb9, 0xda, 0x85, 0x3f, 0x41, 0xbf, 0xe0, 0x5a, 0x58, 0x80, 0x5f, 0x66, 0x0b, 0xd8, 0x90,
	0x35, 0xd5, 0xc0, 0xa7, 0x33, 0x06, 0x65, 0x69, 0x45, 0x00, 0x94, 0x56, 0x6d, 0x98, 0x9b, 0x76,
	0x97, 0xfc, 0xb2, 0xc2, 0xb0, 0xfe, 0xdb, 0x20, 0xe1, 0xeb, 0xd6, 0xe4, 0xdd, 0x47, 0x4a, 0x1d,
	0x42, 0xed, 0x9e, 0x6e, 0x49, 0x3c, 0xcd, 0x43, 0x27, 0xd2, 0x07, 0xd4, 0xde, 0xc7, 0x67, 0x18,
	0x89, 0xcb, 0x30, 0x1f, 0x8d, 0xc6, 0x8f, 0xaa, 0xc8, 0x74, 0xdc, 0xc9, 0x5d, 0x5c, 0x31, 0xa4,
	0x70, 0x88, 0x61, 0x2c, 0x9f, 0x0d, 0x2b, 0x87, 0x50, 0x82, 0x54, 0x64, 0x26, 0x7d, 0x03, 0x40,
	0x34, 0x4b, 0x1c, 0x73, 0xd1, 0xc4, 0xfd, 0x3b, 0xcc, 0xfb, 0x7f, 0xab, 0xe6, 0x3e, 0x5b, 0xa5,
	0xad, 0x04, 0x23, 0x9c, 0x14, 0x51, 0x22, 0xf0, 0x29, 0x79, 0x71, 0x7e, 0xff, 0x8c, 0x0e, 0xe2,
	0x0c, 0xef, 0xbc, 0x72, 0x75, 0x6f, 0x37, 0xa1, 0xec, 0xd3, 0x8e, 0x62, 0x8b, 0x86, 0x10, 0xe8,
	0x08, 0x77, 0x11, 0xbe, 0x92, 0x4f, 0x24, 0xc5, 0x32, 0x36, 0x9d, 0xcf, 0xf3, 0xa6, 0xbb, 0xac,
	0x5e, 0x6c, 0xa9, 0x13, 0x57, 0x25, 0xb5, 0xe3, 0xbd, 0xa8, 0x3a, 0x01, 0x05, 0x59, 0x2a, 0x46}

type twofishContext struct {
	keysize        int
	mode           Mode
	verbose        bool
	key            uint64
	keyBlock       []uint16
	keyFilepath    string
	outputFilepath string
	inputFile      *os.File
	outputFile     *os.File
	keyFile        *os.File
}

// Logging method that prints to console when verbose mode is set
func (tf *twofishContext) LogInfo(msg string, args ...interface{}) {
	if tf.verbose {
		fmt.Printf("log:    ")
		fmt.Printf(msg, args...)
		fmt.Printf("\n")
	}
}

func checkError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Print("\n")
	fmt.Println("encryption mode:")
	fmt.Println("    twofish -e [-v] <text filepath> <key filepath> <output filepath>")
	fmt.Print("\n")
	fmt.Println("decryption mode:")
	fmt.Println("    twofish -d [-v] <ciphertext filepath> <key filepath> <output filepath>")
	fmt.Print("\n")
}

func uint64ToHex(n uint64) string {
	return fmt.Sprintf("%x", n)
}

// Reverses a slice of 8-bit integers in place.
// Used for key generation in decryption.
func reverseSlice(arr []uint8) {
	for i := len(arr)/2 - 1; i >= 0; i-- {
		opp := len(arr) - 1 - i
		arr[i], arr[opp] = arr[opp], arr[i]
	}
}

// Converts a unsigned 64-bit integer into
// a slice of four 16-bit integers.
func int64ToKeyBlock(num uint64, keyblock []uint16) {
	keyblock[3] = uint16(num) | keyblock[3]
	num >>= 16
	keyblock[2] = uint16(num) | keyblock[2]
	num >>= 16
	keyblock[1] = uint16(num) | keyblock[1]
	num >>= 16
	keyblock[0] = uint16(num) | keyblock[0]
}

// Attempts to read 16 hex characters from the cipher file
// and convert the characters into four 16-bit integers. There
// should never be less than 16 characters read since encryption
// always writes 16 hex characters to the cipher file.
// Returns a uint16 slice of length 4.
func getCipherBlock(inputFile *os.File) []uint16 {
	buf := make([]byte, 16)
	_, err := inputFile.Read(buf)
	if err != nil {
		return nil
	}

	words := make([]uint16, 4)
	n, err := strconv.ParseUint(string(buf), 16, 64)
	int64ToKeyBlock(n, words)
	return words
}

// Reads a block comprising of 64 bits from the input file.
// If decryption mode is set, the bytes read from the input file
// are treated as hex (cipherBlock()).
//
// If encryption mode is set, 8 characters are read at a time converted
// into 4 16-bit integers. If there are less than 8 characters
// left in the file, the rightmost bits of the words are set to zero.
// Returns a uint16 slice of length 4.
func getBlock(inputFile *os.File, mode Mode) []uint16 {
	if mode == Decrypt {
		return getCipherBlock(inputFile)
	}

	buf := make([]byte, 8)
	_, err := inputFile.Read(buf)
	if err != nil {
		return nil
	}

	words := make([]uint16, 4)
	words[0] = binary.BigEndian.Uint16(buf[:2])
	words[1] = binary.BigEndian.Uint16(buf[2:4])
	words[2] = binary.BigEndian.Uint16(buf[4:6])
	words[3] = binary.BigEndian.Uint16(buf[6:8])
	return words
}

// getKey attempts to read 16 characters from keyFile.
// Each character in the file represents a 16-bit hex value.
// It returns the number of characters read from keyFile.
func getKey(tf *twofishContext) int {
	buf := make([]byte, 16)
	n, err := tf.keyFile.Read(buf)
	if err != nil {
		fmt.Printf("Read error: %v\n", err)
		return -1
	}
	tf.key = binary.BigEndian.Uint64(buf)
	fmt.Println(tf.key)
	// hexStr := hex.EncodeToString(buf)
	// tf.key, err = strconv.ParseUint(hexStr, 16, 64)
	// if err != nil {
	// 	fmt.Fprintf(os.Stderr, "%v\n", err)
	// 	return -1
	// }

	tf.keyFile.Close()
	return n
}

// returns true if the filename is a file.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}

	return !info.IsDir()
}

// Writes decrypted cipher text to the intended output file.
// Decryption processes 64-bit blocks at a time, and converts
// the result to a 64-bit integer. The integer is broken up into
// 8-bit ascii characters and written to the output file.
func writeOutput(res uint64, tf *twofishContext) {
	if tf.mode == Encrypt {
		hexStr := uint64ToHex(res)
		_, err := tf.outputFile.Write([]byte(hexStr))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	} else { // Decrypt
		var c int8
		var str string
		for i := 0; i < 8; i++ {
			c = int8(res) | c
			if c != 0 {
				str = string(rune(c)) + str
				c = 0
			}
			res >>= 8
		}

		_, err := tf.outputFile.Write([]byte(str))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
}

// Writes encrypted input characters as hexidecimal
// to the cipher file.
func outputHex(res uint64, tf *twofishContext) {
	hexStr := uint64ToHex(res)
	n, err := tf.outputFile.Write([]byte(hexStr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	tf.LogInfo("Wrote %d bytes to cipher file", n)
}

// Generates a random hex string of the length of the byte array
// and stores it in a new key file specified by tf.keyFilepath.
//
// Note: generateKey is only ever called if the user-specified file
// of a key does not exist and needs created.
//
// Returns the length of the generated key or -1 upon error.
func generateKey(tf *twofishContext) int {
	var n int
	buf := make([]uint8, 16)

	// Generate random key
	n, err := rand.Read(buf)
	if err != nil || n != tf.keysize {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}
	fmt.Println(buf)
	fmt.Println(fmt.Sprintf("%x", buf))

	tf.key = binary.BigEndian.Uint64(buf)
	fmt.Println(binary.BigEndian.Uint64(buf))

	// Create the new file and write the key
	f, err := os.Create(tf.keyFilepath)
	checkError(err)

	_, err = f.Write(buf)
	checkError(err)

	tf.LogInfo("Generated key of size %d", n)
	tf.LogInfo("Stored at file: %s", tf.keyFilepath)
	f.Close()
	return len(buf)
}

// Generates twelve 8-bit subkeys for f() and g() rounds
// and updates the 64-bit key by shifting 1 bit for each subkey generated.
// Updates the 8-bit integer slice of twelve subkeys.
func generateSubkeys(round int, subkeys []uint8, tf *twofishContext) {
	index := 0

	if tf.mode == Encrypt {
		for i := 0; i < 4; i++ {
			subkeys[index] = k(&tf.key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = k(&tf.key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = k(&tf.key, 4*round+i)
			index++
		}
	} else { // Generate subkeys in reverse order
		for i := 0; i < 4; i++ {
			subkeys[index] = d(&tf.key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = d(&tf.key, 4*round+i)
			index++
		}

		for i := 0; i < 4; i++ {
			subkeys[index] = d(&tf.key, 4*round+i)
			index++
		}
		reverseSlice(subkeys)
	}
}

// Updates the key by rotating it right by 1 digit.
// Returns an 8-bit integer from the original key based on round % 8.
func d(key *uint64, round int) uint8 {
	var keyalias uint64 = *key
	index := round % 8

	for index < 7 {
		keyalias >>= 8
		index++
	}

	*key = bits.RotateLeft64(*key, -1)
	return uint8(keyalias)
}

// Updates the key by rotating to the left by 1 bit.
// Returns an 8-bit integer from the rotated key based on round % 8.
func k(key *uint64, round int) uint8 {
	*key = bits.RotateLeft64(*key, 1)
	var keyalias uint64 = *key

	for i := 0; i < round%8; i++ {
		keyalias >>= 8
	}
	return uint8(keyalias)
}

// Initalizes remaining fields in tf by setting the key
// and the input/output file descriptors.
func parseArgs(tf *twofishContext) {
	if len(os.Args) < 5 {
		fmt.Println("Incorrect command-line arguments")
		printHelp()
		os.Exit(1)
	}

	flag := os.Args[1]
	if flag == "-e" {
		tf.mode = Encrypt
	} else if flag == "-d" {
		tf.mode = Decrypt
	} else {
		fmt.Println("Unknown encryption mode")
		os.Exit(1)
	}

	index := 2

	// Check verbose flag
	if os.Args[index] == "-v" {
		tf.verbose = true
		index++
	}

	// Get input file
	textFile, err := os.Open(os.Args[index])
	index++
	checkError(err)
	tf.inputFile = textFile

	// Check for key file/generate key
	keyFile, err := os.Open(os.Args[index])
	tf.keyFilepath = os.Args[index]
	index++

	// Generate new key and file
	if err != nil {
		tf.LogInfo("%s does not exist", tf.keyFilepath)
		generateKey(tf)
		err = nil
	} else { // Read key from existing file
		tf.keyFile = keyFile
		n := getKey(tf)
		if n != tf.keysize {
			tf.LogInfo("Key size is %d bytes", n)
			fmt.Fprintf(os.Stderr, "key size must be 8 bytes\n")
			os.Exit(1)
		}
	}
	tf.outputFilepath = os.Args[index]

	// Already a ciphertext file, kill the program
	if fileExists(tf.outputFilepath) {
		if tf.mode == Encrypt {
			fmt.Fprintf(os.Stderr, "Unable to encrypt: an output file exists at %s\n", tf.outputFilepath)
			fmt.Fprintf(os.Stderr, "Delete the output file to encrypt\n")
		} else {
			fmt.Fprintf(os.Stderr, "Unable to decrypt: an output file exists at %s\n", tf.outputFilepath)
			fmt.Fprintf(os.Stderr, "Delete the output file to decrypt\n")
		}
		tf.inputFile.Close()
		os.Exit(1)
	}

	tf.outputFile, err = os.Create(tf.outputFilepath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		tf.inputFile.Close()
		tf.outputFile.Close()
		os.Exit(1)
	}
}

// Permutates the 16-bit word using 4 subkeys.
// Returns a new 16-bit integer.
func g(word uint16, subkeys []uint8) uint16 {
	var g1, g2 uint8

	g2 = g2 | uint8(word)
	word >>= 8
	g1 = g1 | uint8(word)
	g3 := ftable[(g2^subkeys[0])] ^ g1
	g4 := ftable[(g3^subkeys[1])] ^ g2
	g5 := ftable[(g4^subkeys[2])] ^ g3
	g6 := ftable[(g5^subkeys[3])] ^ g4
	var ans uint16
	ans |= uint16(g5)
	ans <<= 8
	ans |= uint16(g6)
	return ans
}

// Generates subkeys and performs permutations and concatenations
// on r0 and r1.
// Returns two 16-bit integers.
func f(round int, r0, r1 uint16, tf *twofishContext) (uint16, uint16) {
	subkeys := make([]uint8, 12)
	generateSubkeys(round, subkeys, tf)

	t0 := g(r0, subkeys[0:4])
	t1 := g(r1, subkeys[4:8])

	var t3, t4 uint16
	t3 |= uint16(subkeys[8])
	t3 <<= 8
	t3 |= uint16(subkeys[9])
	t4 |= uint16(subkeys[10])
	t4 <<= 8
	t4 |= uint16(subkeys[11])

	f0 := uint32(t0+2*t1+t3) % uint32(math.Pow(2, 16))
	f1 := uint32(2*t0+t1+t4) % uint32(math.Pow(2, 16))
	return uint16(f0), uint16(f1)
}

// Алгоритм шифрования и расшифрования Twofish.
//
// -- Шифрование --
// Считывает и шифрует 64 бита входного файла за раз и записывает
// результат в шестнадцатеричном формате в выходной файл. Каждый блок проходит через 16 раундов
// преобразований.
//
// -- Дешифрование --
// Считывает по 16 шестнадцатеричных символов за раз из файла с шифром
// и записывает полученные символы ASCII в выходной файл. Каждый блок проходит
// через 16 раундов преобразований.
func twofish(tf *twofishContext) {
	var block []uint16 = getBlock(tf.inputFile, tf.mode)
	if block == nil {
		fmt.Fprintf(os.Stderr, "Error getting block from input file\n")
		os.Exit(1)
	}

	var res uint64
	for block != nil {
		int64ToKeyBlock(tf.key, tf.keyBlock)

		// whitening step
		r0 := block[0] ^ tf.keyBlock[0]
		r1 := block[1] ^ tf.keyBlock[1]
		r2 := block[2] ^ tf.keyBlock[2]
		r3 := block[3] ^ tf.keyBlock[3]
		round := 0

		for round < 16 {
			f0, f1 := f(round, r0, r1, tf)
			var r0_temp, r1_temp uint16

			if tf.mode == Encrypt {
				r0_temp = bits.RotateLeft16(r2^f0, -1)
				r1_temp = bits.RotateLeft16(r3, 1) ^ f1
			} else {
				r0_temp = bits.RotateLeft16(r2, 1) ^ f0
				r1_temp = bits.RotateLeft16(r3^f1, -1)
			}
			r2, r3, r0, r1 = r0, r1, r0_temp, r1_temp
			round++
		}

		// output whitening step
		res |= uint64(r2 ^ tf.keyBlock[0])
		res <<= 16
		res |= uint64(r3 ^ tf.keyBlock[1])
		res <<= 16
		res |= uint64(r0 ^ tf.keyBlock[2])
		res <<= 16
		res |= uint64(r1 ^ tf.keyBlock[3])

		writeOutput(res, tf)
		block = getBlock(tf.inputFile, tf.mode)
		res = 0
	}
	tf.inputFile.Close()
	tf.outputFile.Close()
}

func main() {
	// tf := twofishContext{
	// 	keyBlock: make([]uint16, 4),
	// 	keysize:  16,
	// 	verbose:  false}

	// parseArgs(&tf)
	// twofish(&tf)
	TestAlgoEncryption()
}

// func randomFileString(n int) string {
// 	bytes := make([]byte, n)
// 	for i := 0; i < n; i++ {
// 		bytes[i] = byte(65 + rand.Intn(25)) // A - Z
// 	}
// 	return string(bytes)
// }

func generateAlgoTestKey(tf *twofishContext) int {
	var n int
	buf := make([]uint8, 16)

	// Generate random key
	n, err := rand.Read(buf)
	if err != nil || n != tf.keysize {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return -1
	}

	tf.key = binary.BigEndian.Uint64(buf)
	fmt.Println("Key: ", binary.BigEndian.Uint64(buf))

	tf.LogInfo("Generated key of size %d", n)

	return len(buf)
}

func TestAlgoEncryption() {
	plaintext := "hello there, this is a string!"
	// randStr := randomFileString(6)

	// Encryption
	input, err := os.Create("input")
	if err != nil {
		fmt.Errorf("%v\n", err)
	}

	_, err = input.Write([]byte(plaintext))
	if err != nil {
		fmt.Errorf("%v\n", err)
	}
	input.Seek(0, io.SeekStart)

	cipherFile, err := os.Create("cipher")
	if err != nil {
		fmt.Errorf("%v\n", err)
	}

	tf := twofishContext{
		inputFile:  input,
		keyBlock:   make([]uint16, 4),
		keysize:    16,
		mode:       Encrypt,
		outputFile: cipherFile,
		verbose:    false,
	}
	generateAlgoTestKey(&tf)
	twofish(&tf)

	// Decryption
	tf.inputFile, err = os.Open("cipher")
	if err != nil {
		fmt.Errorf("%v\n", err)
	}

	tf.outputFile, err = os.Create("output")
	if err != nil {
		fmt.Errorf("%v\n", err)
	}
	tf.mode = Decrypt
	twofish(&tf)

	// Veryfiy plain text equals decrypted text
	outputFile, _ := os.Open("output")
	outputText := make([]byte, 200)
	n, _ := outputFile.Read(outputText)

	if plaintext != string(outputText[0:len(plaintext)]) && n != len(plaintext) {
		fmt.Println("encryption error: plain text and output text don't match")
		fmt.Printf("plain: %s\n", plaintext)
		fmt.Printf("output: %s\n", string(outputText[:n]))
	}

	// _ = os.Remove("input" + randStr)
	// _ = os.Remove("cipher" + randStr)
	// _ = os.Remove("output" + randStr)
}
