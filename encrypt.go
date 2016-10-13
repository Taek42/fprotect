package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/Taek42/speakeasy"
	"golang.org/x/crypto/nacl/box"
)

// harden will take a password and turn it into an io.Reader that can seed the
// key generation. The io.Reader has slightly stronger secuirty properties than
// the input password.
func harden(password string) io.Reader {
	// Require fprotect-specific rainbow tables to crack passwords.
	password = "simplefprotectsalt-ylhhqgibiyeh"+password

	// Harden with 25,000 rounds of sha256.
	hashedPW := sha256.Sum256([]byte(password))
	for i := 0; i < 25e3; i++ {
		hashedPW = sha256.Sum256(hashedPW[:])
	}
	return bytes.NewReader(hashedPW[:])
}

// genPubKey will query the user for a password, then generate a pubkey using
// that password.
func genPubKey() (userRejects bool, secKey *[32]byte, err error) {
	// Ask the user if they would like to generate a pubkey.
	for {
		fmt.Println("Pubkey not found. Would you like to generate one? (y/n)")
		var  result []byte
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
		if (string(result) == "y" || string(result) == "yes" || string(result) == "Y" || string(result) == "Yes" || string(result) == "YES") {
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

	// Harden the password and use it for key derivation.
	readerPW := harden(password)
	pubKey, secKey, err := box.GenerateKey(readerPW)
	if err != nil {
		return false, nil, errors.New("key derivation unsuccessful: " + err.Error())
	}

	// Save pubkey to disk.
	err = ioutil.WriteFile(pubKeyLocation, pubKey[:], 0400)
	if err != nil {
		return false, nil, errors.New("unable to write pubkey to disk: " + err.Error())
	}
	return false, secKey, nil
}

// encrypt will create an encrypted file using the user's fprotect pubkey,
// getting the plaintext from a stdin file and using the second program
// argument to determine where the encrypted data should be written. encrypt is
// cautious, and will not overwrite any existing files.
func encrypt() {
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

	// Check that the pubkey exists. If not, ask the user, then ask for a
	// password. This check happens after reading the file from stdin, as
	// we will want to query the user if the pubkey does not exist.
	var secKey *[32]byte
	pubKeyFile, err := os.Open(pubKeyLocation)
	if os.IsNotExist(err) {
		// Go through the pubkey generation dialog.
		var userRejects bool
		var err error
		userRejects, secKey, err = genPubKey()
		if userRejects {
			return
		}
		if err != nil {
			fmt.Println("unable to generate public key:", err)
			return
		}

		// Load the pubkey file. This is a sanity check as opposed to
		// something that is strictly necessary.
		pubKeyFile, err = os.Open(pubKeyLocation)
		if err != nil {
			fmt.Println("generated pubkey cannot be read:", err)
			return
		}
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

	// Generate a nonce.
	nonce := new([24]byte)
	_, err = rand.Read(nonce[:])
	if err != nil {
		fmt.Println("unable to get entropy to perform encryption:", err)
		return
	}

	// Fetch the verification key if not already available.
	if secKey == nil {
		password, err := speakeasy.Ask("For authentication, please provide fprotect password: ")
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
	}

	// Encrypt the data.
	ciphertext := box.Seal(nil, plaintext, nonce, boxKey, secKey)

	// Write the result.
	wholeFile := append(nonce[:], ciphertext...)
	err = ioutil.WriteFile(outFilename, wholeFile, 0400)
	if err != nil {
		fmt.Println("unable to write encrypted result:", err)
	}
	fmt.Println("Encrypted file created successfully.")
}
