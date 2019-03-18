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

// Package argon2id provides some helper functions around hashing and comparing password hashes using Argon2id.
package argon2id

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// ErrInvalidHash is an error when the hashed password does not match the proper pattern
var ErrInvalidHash = errors.New("synacor/argon2id: the hashed password is not a valid hash")

// ErrInvalidComplexity is an error when a complexity value (time, memory, threads) is too large
var ErrInvalidComplexity = errors.New("synacor/argon2id: the hashed password has invalid complexity values")

// ErrInvalidArgon2Version is an error when the version in the hashed password does not match the version supplied by the golang.org/x/crypto/argon2 library
var ErrInvalidArgon2Version = fmt.Errorf("synacor/argon2id: argon2 version is not %d", argon2.Version)

// ErrMismatchedHashAndPassword is an error when the password does not hash to the hashedPassword value
var ErrMismatchedHashAndPassword = errors.New("synacor/argon2id: hashedPassword is not the hash of the given password")

// Uses unix/crypt alphabet: https://en.wikipedia.org/wiki/Base64#Radix-64_applications_not_compatible_with_Base64
var encoding = base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

// 16 bytes is the recommended size for password hashing (https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-3.1)
const saltLen = 16

type hashed struct {
	time    uint32
	memory  uint32
	threads uint8
	hash    []byte
	salt    []byte
}

// t=1 is recommended for Argon2id variant (https://tools.ietf.org/html/draft-irtf-cfrg-argon2-03#section-9.4)
const defaultTime uint32 = 1

// memory=64MiB is a sane default mentioned in the golang library (https://godoc.org/golang.org/x/crypto/argon2#IDKey)
const defaultMemory uint32 = 64 * 1024 // 64 MiB

// threads=64MiB is a sane default mentioned in the golang library (https://godoc.org/golang.org/x/crypto/argon2#IDKey)
const defaultThreads uint8 = 4

const defaultKeyLen uint32 = 32

var rx = regexp.MustCompile(`^\$argon2id([0-9]{1,4})\$([0-9]{1,10}),([0-9]{1,10}),([0-9]{1,3})\$([./a-zA-Z0-9]+)\$([./a-zA-Z0-9]+)$`)

// IsHashedPassword will return true if hashedPassword is a proper password hashed by this library
func IsHashedPassword(hashedPassword string) bool {
	return rx.MatchString(hashedPassword)
}

// DefaultHashPassword is a convenience function that calls HashPassword() with default values
func DefaultHashPassword(password string) (string, error) {
	return HashPassword(password, 0, 0, 0, 0)
}

// HashPassword will hash the password. If time, memory, threads or keyLen is "0", then a sane default will be used.
func HashPassword(password string, time, memory uint32, threads uint8, keyLen uint32) (string, error) {
	if time == 0 {
		time = defaultTime
	}

	if memory == 0 {
		memory = defaultMemory
	}

	if threads == 0 {
		threads = defaultThreads
	}

	if keyLen == 0 {
		keyLen = defaultKeyLen
	}

	salt, err := generateSalt()
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
	return fmt.Sprintf("$argon2id%d$%d,%d,%d$%s$%s", argon2.Version, time, memory, threads, encoding.EncodeToString(salt), encoding.EncodeToString(hash)), nil
}

// Compare will compare the hashedPassword with the supplied password. If unsuccessful, an error will be returned. On success, error is nil.
func Compare(hashedPassword, password string) error {
	h, err := newHashedFromHashedPassword(hashedPassword)
	if err != nil {
		return err
	}

	compareHash := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.hash)))
	if subtle.ConstantTimeCompare(h.hash, compareHash) == 1 {
		return nil
	}

	return ErrMismatchedHashAndPassword
}

func newHashedFromHashedPassword(hashedPassword string) (*hashed, error) {
	match := rx.FindStringSubmatch(hashedPassword)
	if match == nil {
		return nil, ErrInvalidHash
	}

	// we don't need to error check the integer conversion here because the regex ensures they are a numeric and under 32 bytes
	version, _ := strconv.Atoi(match[1])
	time, _ := strconv.Atoi(match[2])
	memory, _ := strconv.Atoi(match[3])
	threads, _ := strconv.Atoi(match[4])
	salt, hash := match[5], match[6]

	if version != argon2.Version {
		return nil, ErrInvalidArgon2Version
	}

	rawHash, err := encoding.DecodeString(hash)
	if err != nil {
		return nil, err
	}

	rawSalt, err := encoding.DecodeString(salt)
	if err != nil {
		return nil, err
	}

	// prevent overflow errors
	if time == 0 || time > math.MaxUint32 || memory > math.MaxUint32 || threads == 0 || threads > math.MaxUint8 {
		return nil, ErrInvalidComplexity
	}

	return &hashed{
		time:    uint32(time),
		memory:  uint32(memory),
		threads: uint8(threads),
		hash:    rawHash,
		salt:    rawSalt,
	}, nil
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLen)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}

	return salt, nil
}
