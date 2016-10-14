package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

const (
	version = "0.0.1"
)

var (
	keyVerifierLocation string
)

func help() {
	fmt.Println("check README at github.com/Taek42/fprotect")
	fmt.Println("fprotect is a utility to encrypt and decrypt files on\ndisk, printing the file to stdout after decryption.\n")
	usage()
}

func usage() {
	fmt.Println(`Usage:
	fprotect encrypt [inputFilename] [outputFilename]
	fprotect display [optional flag --quiet] [inputFilename]
	fprotect version

If using the --quiet flag, you must still type the decryption
password, but you will not be prompted.`)
}

func main() {
	// Handle any basic cases.
	if len(os.Args) < 2 {
		usage()
		return
	}
	if len(os.Args) == 2 {
		if os.Args[1] == "-v" || os.Args[1] == "--version" || os.Args[1] == "version" {
			fmt.Printf("fprotect v%v\n", version)
			return
		} else if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
			help()
			return
		}
		usage()
		return
	}

	// Identify the pubkey location.
	keyVerifierLocation = os.Getenv("FPROTECTVERIFIER")
	if keyVerifierLocation == "" {
		homeDir, err := homedir.Dir()
		if err != nil {
			fmt.Println("unable to access homedir for the fprotect pubkey, consider setting environment variable FPROTECTVERIFIER:", err)
			return
		}
		keyVerifierLocation = filepath.Join(homeDir, ".config", "fprotect.pubkey")
	}

	if os.Args[1] == "encrypt" {
		if os.Args[2] == "--help" || os.Args[2] == "-h" {
			help()
			return
		}
		if len(os.Args) != 4 {
			usage()
			return
		}
		encrypt()
		return
	} else if os.Args[1] == "display" {
		if os.Args[2] == "--help" || os.Args[2] == "-h" {
			help()
			return
		}
		if len(os.Args) == 3 {
			quiet := false
			display(quiet)
			return
		}
		if len(os.Args) == 4 {
			if os.Args[2] == "--quiet" || os.Args[2] == "-q" {
				quiet := true
				display(quiet)
				return
			}
			usage()
			return
		}
		usage()
		return
	}
	usage()
	return
}
