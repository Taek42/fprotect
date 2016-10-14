package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/Taek42/speakeasy"
)

// display will take a key from the user, open the encrypted file, decrypt it,
// and print it to stdout.
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

	// Fetch the decryption key.
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
	secKey := harden(password)

	plaintext, err := decryptBytes(secKey, ciphertext)
	if err != nil {
		fmt.Println("decryption failed:", err)
		return
	}
	fmt.Print(string(plaintext))
}
