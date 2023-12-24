package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
)

func TestInt64ToKeyblock(t *testing.T) {
	var num uint64 = 12977601823743685594
	arr := make([]uint16, 4)
	int64ToKeyBlock(num, arr)

	if arr[0] != 46105 || arr[1] != 46105 || arr[2] != 46260 || arr[3] != 13274 {
		t.Errorf("uint16 block was incorrect\n")
		t.Errorf("expected: %d %d %d %d", 46105, 46105, 46260, 13274)
		t.Errorf("got: %d %d %d %d", arr[0], arr[1], arr[2], arr[3])
	}
}

func TestReverseSlice(t *testing.T) {
	arr := []uint8{1, 2, 3, 4, 5}
	reverseSlice(arr)

	for i := len(arr) - 1; i >= 0; i-- {
		if arr[i] != uint8(5-i) {
			t.Error("reverseSlice() failed")
			t.Errorf("expected %d, got: %d\n", uint8(5-i), arr[i])
		}
	}
}

func randomString(n int) string {
	bytes := make([]byte, n)
	for i := 0; i < n; i++ {
		bytes[i] = byte(65 + rand.Intn(25)) // A - Z
	}
	return string(bytes)
}

func generateTestKey(tf *twofishContext) int {
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

func TestEncryption(t *testing.T) {
	plaintext := "hello there, this is a string to test !"
	randStr := randomString(6)

	// Encryption
	input, err := os.Create("input" + randStr)
	if err != nil {
		t.Errorf("%v\n", err)
	}

	_, err = input.Write([]byte(plaintext))
	if err != nil {
		t.Errorf("%v\n", err)
	}
	input.Seek(0, io.SeekStart)

	cipherFile, err := os.Create("cipher" + randStr)
	if err != nil {
		t.Errorf("%v\n", err)
	}

	tf := twofishContext{
		inputFile:  input,
		keyBlock:   make([]uint16, 4),
		keysize:    16,
		mode:       Encrypt,
		outputFile: cipherFile,
		verbose:    false,
	}
	generateTestKey(&tf)
	twofish(&tf)

	// Decryption
	tf.inputFile, err = os.Open("cipher" + randStr)
	if err != nil {
		t.Errorf("%v\n", err)
	}

	tf.outputFile, err = os.Create("output" + randStr)
	if err != nil {
		t.Errorf("%v\n", err)
	}
	tf.mode = Decrypt
	twofish(&tf)

	// Veryfiy plain text equals decrypted text
	outputFile, _ := os.Open("output" + randStr)
	outputText := make([]byte, 100)
	n, _ := outputFile.Read(outputText)

	if plaintext != string(outputText[0:len(plaintext)]) && n != len(plaintext) {
		t.Errorf("encryption error: plain text and output text don't match\n")
		t.Errorf("plain: %s\n", plaintext)
		t.Errorf("output: %s\n", string(outputText[:n]))
	}

	_ = os.Remove("input" + randStr)
	_ = os.Remove("cipher" + randStr)
	_ = os.Remove("output" + randStr)
}
