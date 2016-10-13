package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Taek42/speakeasy"
	"golang.org/x/crypto/nacl/box"
)

func display(quiet bool) {
	// Read the input file.
	var inFilename string
	if quiet {
		inFilename = os.Args[3]
	} else {
		inFilename = os.Args[2]
	}
	ciphertext, err := ioutil.ReadFile(inFilename)
	if err != nil {
		fmt.Println("unable to read file from stdin:", err)
		return
	}
	// Verify that the file is long enough to decrypt safely.
	if len(ciphertext) < box.Overhead + 24 {
		fmt.Println("unable to decrypt file - missing header data")
		return
	}

	// Check that the pubkey exists. If not, ask the user, then ask for a
	// password. This check happens after reading the file from stdin, as
	// we will want to query the user if the pubkey does not exist.
	var secKey *[32]byte
	pubKeyFile, err := os.Open(pubKeyLocation)
	if os.IsNotExist(err) {
		fmt.Println("no fprotect pubkey file found, consider setting environment variable FPROTECTPUBKEY")
		return
	} else if err != nil {
		fmt.Println("unable to open the fprotect pubkey file:", err)
		return
	}
	defer pubKeyFile.Close()
	pubKey, err := ioutil.ReadAll(pubKeyFile)
	if err != nil {
		fmt.Println("unable to read the fprotect pubkey:", err)
		return
	}

	// Verify the pubkey, and change it to a type understood by the box
	// package.
	if len(pubKey) != 32 {
		fmt.Println("pubkey is not understood - should be 32 bytes, got", len(pubKey))
		return
	}
	boxKey := new([32]byte)
	copy(boxKey[:], pubKey)

	// Fetch the verification key.
	var password string
	if quiet {
		password, err = speakeasy.QuietAsk()
	} else {
		password, err = speakeasy.Ask("For decryption, please provide fprotect password: ")
	}
	if err != nil {
		fmt.Println("unable to read password: " + err.Error())
		return
	}
	readerPW := harden(password)
	_, secKey, err = box.GenerateKey(readerPW)
	if err != nil {
		fmt.Println("key derivation unsuccessful: " + err.Error())
		return
	}

	// Read the nonce from the file.
	nonce := new([24]byte)
	copy(nonce[:], ciphertext)
	plaintext, success := box.Open(nil, ciphertext[24:], nonce, boxKey, secKey)
	if !success {
		fmt.Println("decryption failed")
		return
	}
	fmt.Print(string(plaintext))
}
