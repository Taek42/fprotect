package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/Taek42/speakeasy"
)

// genVerifier will query the user for a password, then generate a key verifier
// using that password.
func genVerifier() (userRejects bool, secKey []byte, err error) {
	// Ask the user if they would like to generate a key verifier.
	for {
		fmt.Println("Key verifier not found. Would you like to generate one? (y/n)")
		var result []byte
		b := bufio.NewReader(os.Stdin)
		isPrefix := true
		for isPrefix {
			var newBytes []byte
			var err error
			newBytes, isPrefix, err = b.ReadLine()
			if err == io.EOF {
				continue
			}
			if err != nil {
				return false, nil, errors.New("unable to read user response: " + err.Error())
			}
			result = append(result, newBytes...)
		}
		if string(result) == "n" || string(result) == "no" || string(result) == "N" || string(result) == "No" || string(result) == "NO" {
			return true, nil, nil
		}
		if string(result) == "y" || string(result) == "yes" || string(result) == "Y" || string(result) == "Yes" || string(result) == "YES" {
			break
		}
		fmt.Println("Response not recognized. Would you like to generate a new pubkey? (y/n)")
	}

	// User has signaled that they would like to generate a pubkey. Query a
	// password for this pubkey.
	password, err := speakeasy.Ask("Please provide a password: ")
	if err != nil {
		return false, nil, errors.New("unable to read password: " + err.Error())
	}
	passwordConfirm, err := speakeasy.Ask("Confirm: ")
	if err != nil {
		return false, nil, errors.New("unable to read password: " + err.Error())
	}
	if password != passwordConfirm {
		return false, nil, errors.New("passwords do not match")
	}

	// Harden the password and use it to create the verifier.
	secKey = harden(password)
	plainVerifier := make([]byte, 32)
	verifier, err := encryptBytes(secKey, plainVerifier)
	if err != nil {
		return false, nil, errors.New("unable to encrypt verifier: " + err.Error())
	}

	// Write the verifier to disk.
	err = ioutil.WriteFile(keyVerifierLocation, verifier, 0400)
	if err != nil {
		return false, nil, errors.New("unable to write verifier to disk: " + err.Error())
	}
	return false, secKey, nil
}

// encrypt will create an encrypted file using the user's fprotect pubkey,
// getting the plaintext from a stdin file and using the second program
// argument to determine where the encrypted data should be written. encrypt is
// cautious, and will not overwrite any existing files.
func encrypt() {
	// Check that the user key verifier exists.
	var secKey []byte
	verifier, err := ioutil.ReadFile(keyVerifierLocation)
	if os.IsNotExist(err) {
		// Go through the pubkey generation dialog.
		var userRejects bool
		var err error
		userRejects, secKey, err = genVerifier()
		if userRejects {
			return
		}
		if err != nil {
			fmt.Println("unable to generate public key:", err)
			return
		}

		// Load the pubkey file. This is a sanity check as opposed to
		// something that is strictly necessary.
		verifier, err = ioutil.ReadFile(keyVerifierLocation)
		if err != nil {
			fmt.Println("generated pubkey cannot be read:", err)
			return
		}
	} else if err != nil {
		fmt.Println("unable to open the fprotect pubkey file:", err)
		return
	}

	// Read the input file.
	inFilename := os.Args[2]
	plaintext, err := ioutil.ReadFile(inFilename)
	if err != nil {
		fmt.Println("unable to read file from stdin:", err)
		return
	}

	// Check that the output file does not exist. Do not overwrite existing
	// files.
	outFilename := os.Args[3]
	_, err = os.Stat(outFilename)
	if !os.IsNotExist(err) && outFilename != inFilename {
		fmt.Println("Seems that output file already exists, refusing to overwrite.")
		return
	}

	// Fetch the encryption key if not already available.
	if secKey == nil {
		password, err := speakeasy.Ask("To encrypt, please provide fprotect password: ")
		if err != nil {
			fmt.Println("unable to read password:", err)
			return
		}
		secKey = harden(password)
	}

	// Verify that the secKey is correct.
	expected := make([]byte, 32)
	decVerification, err := decryptBytes(secKey, verifier)
	if err != nil {
		fmt.Println("unable to decrypt user key verifier:", err.Error())
		return
	}
	if !bytes.Equal(expected, decVerification) {
		fmt.Println("provided encryption key seems to be incorrect")
		return
	}

	// Encrypt the data and write the result.
	ciphertext, err := encryptBytes(secKey, plaintext)
	if err != nil {
		fmt.Println("encryption failed:", err)
	}
	err = ioutil.WriteFile(outFilename, ciphertext, 0400)
	if err != nil {
		fmt.Println("unable to write encrypted result:", err)
	}
	fmt.Println("Encrypted file created successfully.")
}
