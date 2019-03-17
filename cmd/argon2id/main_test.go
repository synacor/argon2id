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
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/onsi/gomega"
	"github.com/synacor/argon2id"
)

func TestRunCommandWithHelp(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(false, "-h")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusError))
	g.Expect(len(stdout)).Should(gomega.Equal(0))
	g.Expect(stderr).Should(gomega.MatchRegexp("^usage of argon2id"))
}

func TestRunCommandWithoutPassword(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	reset := mockReadPassword([]byte(""), nil)
	defer reset()

	exitStatus, stdout, stderr := runTest(false)
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusError))
	g.Expect(stdout).Should(gomega.Equal(prompt))
	g.Expect(stderr).Should(gomega.Equal("a password is required\n"))
}

func TestRunCommandWithoutPasswordFailure(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	reset := mockReadPassword([]byte(""), errors.New("terminal: could not prompt for password"))
	defer reset()

	exitStatus, stdout, stderr := runTest(false)
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusError))
	g.Expect(stdout).Should(gomega.Equal(prompt))
	g.Expect(stderr).Should(gomega.Equal("could not read password: terminal: could not prompt for password\n"))
}

func TestRunCommandWithDefaultHashing(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	exitStatus, stdout, stderr := runTest(true)
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusNormal))

	// has trailing newline
	g.Expect(stdout[len(stdout)-1]).Should(gomega.Equal(uint8('\n')))
	g.Expect(argon2id.IsHashedPassword(string(stdout[0 : len(stdout)-1]))).Should(gomega.BeTrue())
	g.Expect(len(stderr)).Should(gomega.Equal(0))
}

func TestRunCommandWithHashingError(t *testing.T) {
	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	oldReader := rand.Reader
	defer func() { rand.Reader = oldReader }()
	rand.Reader = bytes.NewBuffer([]byte("incomplete"))

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true)
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusError))
	g.Expect(stdout).Should(gomega.Equal(""))
	g.Expect(stderr).Should(gomega.Equal("could not hash password: unexpected EOF"))
}

func TestRunCommandWithDefaultHashingNoNewline(t *testing.T) {
	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true, "-n")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusNormal))

	// does not have trailing newline
	g.Expect(stdout[len(stdout)-1]).ShouldNot(gomega.Equal(uint8('\n')))
	g.Expect(argon2id.IsHashedPassword(stdout)).Should(gomega.BeTrue())
	g.Expect(len(stderr)).Should(gomega.Equal(0))
}

func TestRunCommandWithDefaultHashingQuiet(t *testing.T) {
	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(false, "-n -q")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusNormal))

	// does not have trailing newline
	g.Expect(stdout[len(stdout)-1]).ShouldNot(gomega.Equal(uint8('\n')))
	g.Expect(argon2id.IsHashedPassword(stdout)).Should(gomega.BeTrue())
	g.Expect(len(stderr)).Should(gomega.Equal(0))
}

func TestRunCommandWithCustomComplexity(t *testing.T) {
	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true, "-n -time 2 -memory 1024 -threads 2 -keylen 24")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusNormal))

	g.Expect(argon2id.IsHashedPassword(stdout)).Should(gomega.BeTrue())
	g.Expect(stdout).Should(gomega.MatchRegexp(`\$2,1024,2\$`))
	g.Expect(len(stdout)).Should(gomega.Equal(76))
	g.Expect(len(stderr)).Should(gomega.Equal(0))
}

func TestRunCommandCompare(t *testing.T) {
	reset := mockReadPassword([]byte("my-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true, "-c $argon2id19$1,65536,4$fjSIS8wLOEZRF/9ceB3Ct.$YCdi8.UQsEGFBsAwVGH/U5lwlvHWLbUl7MzSXwFJ7Oy")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusNormal))

	g.Expect(stdout).Should(gomega.Equal("OK - password matches hashed password\n"))
	g.Expect(len(stderr)).Should(gomega.Equal(0))
}

func TestRunCommandCompareFailure(t *testing.T) {
	reset := mockReadPassword([]byte("different-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true, "-c $argon2id19$1,65536,4$fjSIS8wLOEZRF/9ceB3Ct.$YCdi8.UQsEGFBsAwVGH/U5lwlvHWLbUl7MzSXwFJ7Oy")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusMismatchHashAndPassword))
	g.Expect(len(stdout)).Should(gomega.Equal(0))
	g.Expect(stderr).Should(gomega.Equal(argon2id.ErrMismatchedHashAndPassword.Error() + "\n"))
}

func TestRunCommandCompareWithInvalidHash(t *testing.T) {
	reset := mockReadPassword([]byte("different-password"), nil)
	defer reset()

	g := gomega.NewGomegaWithT(t)

	exitStatus, stdout, stderr := runTest(true, "-c bad-hash")
	g.Expect(exitStatus).Should(gomega.Equal(exitStatusError))
	g.Expect(len(stdout)).Should(gomega.Equal(0))
	g.Expect(stderr).Should(gomega.Equal(argon2id.ErrInvalidHash.Error() + "\n"))
}

func runTest(stripPrompt bool, args ...string) (exitStatus int, stdout, stderr string) {
	stdoutBuffer := bytes.NewBuffer(nil)
	stderrBuffer := bytes.NewBuffer(nil)

	setArgs(args...)
	exitStatus = runCommand(stdoutBuffer, stderrBuffer)
	stdout = stdoutBuffer.String()
	stderr = stderrBuffer.String()

	if stripPrompt {
		stdout = string(stdout[len(prompt)+1:])
	}

	return
}

func setArgs(argStr ...string) {
	args := []string{}
	if len(argStr) > 0 {
		args = strings.Split(argStr[0], " ")
	}

	os.Args = append([]string{"argon2id"}, args...)
}
