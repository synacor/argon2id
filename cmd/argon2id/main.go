/*
argon2id - Go password hashing utility using Argon2
Copyright (C) 2019 Synacor, Inc.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/synacor/argon2id"
)

const prompt = "Password:"

const (
	exitStatusNormal = iota
	exitStatusError
	exitStatusMismatchHashAndPassword
)

func main() {
	exitStatus := runCommand(os.Stdout, os.Stderr)
	os.Exit(exitStatus)
}

// runCommand will return an exit status that can be used with "os.Exit()". That is, "0" signifies success
// and a non-"0" value signifies error.
func runCommand(stdout, stderr io.Writer) int {
	flagset := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flagset.SetOutput(stderr)

	compareHashedPassword := flagset.String("c", "", "a hashed password to compare the password to")
	quiet := flagset.Bool("q", false, "do not print the "+prompt+" text")
	omitNewline := flagset.Bool("n", false, "do not print a trailing newline character")
	timeComplexity := flagset.Int("time", 0, "time complexity when generating hash")
	memoryComplexity := flagset.Int("memory", 0, "memory complexity when generating hash")
	numThreads := flagset.Int("threads", 0, "number of threads to use when generating hash")
	keyLen := flagset.Int("keylen", 0, "keyLen when generating hash")
	help := flagset.Bool("h", false, "show help information")
	flagset.Parse(os.Args[1:])

	if *help {
		usage(flagset, stderr)
		return exitStatusError
	}

	if !*quiet {
		fmt.Fprintf(stdout, prompt)
	}

	pwBytes, err := readPassword(int(syscall.Stdin))
	if err != nil {
		fmt.Fprintf(stderr, "could not read password: %v\n", err)
		return exitStatusError
	}

	if len(pwBytes) == 0 {
		fmt.Fprintf(stderr, "a password is required\n")
		return exitStatusError
	}

	if !*quiet {
		fmt.Fprintln(stdout)
	}

	password := string(pwBytes)

	if len(*compareHashedPassword) > 0 {
		if err := argon2id.Compare(*compareHashedPassword, password); err != nil {
			fmt.Fprintln(stderr, err.Error())
			if err == argon2id.ErrMismatchedHashAndPassword {
				return exitStatusMismatchHashAndPassword
			}

			return exitStatusError
		}

		fmt.Fprintln(stdout, "OK - password matches hashed password")
		return exitStatusNormal
	}

	hashedPassword, err := argon2id.HashPassword(password, uint32(*timeComplexity), uint32(*memoryComplexity), uint8(*numThreads), uint32(*keyLen))
	if err != nil {
		fmt.Fprintf(stderr, "could not hash password: %v", err)
		return exitStatusError
	}

	fmt.Fprint(stdout, hashedPassword)
	if !*omitNewline {
		fmt.Fprintln(stdout, "")
	}

	return exitStatusNormal
}

func usage(flagset *flag.FlagSet, stderr io.Writer) {
	fmt.Fprintf(stderr, "usage of %s...\n", os.Args[0])
	fmt.Fprintf(stderr, "         %s # prompt for password, output a hash of the password\n", os.Args[0])
	fmt.Fprintf(stderr, "         %s -c <hashed-password> [-n] [-time <time-complexity>] [-memory <memory-complexity>] [-threads <num-threads>] [-keylen <key-length>] # compare the password (via prompt) to the hashed-password\n", os.Args[0])

	flagset.PrintDefaults()
}
