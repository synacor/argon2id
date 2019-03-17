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

package argon2id

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"testing"

	"github.com/onsi/gomega"
)

func TestDefaultHashPassword(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h, err := DefaultHashPassword("test")
	g.Expect(err).Should(gomega.Succeed())
	h2, err2 := DefaultHashPassword("test")
	g.Expect(err2).Should(gomega.Succeed())

	g.Expect(h).ShouldNot(gomega.Equal(h2))
	g.Expect(Compare(h, "test")).Should(gomega.Succeed())
	g.Expect(Compare(h, "bad-password")).ShouldNot(gomega.Succeed())
	g.Expect(Compare(h, "bad-password")).Should(gomega.Equal(ErrMismatchedHashAndPassword))
	g.Expect(h).Should(gomega.MatchRegexp(`^\Q$argon2id19$1,65536,4$`))
	g.Expect(len(h)).Should(gomega.Equal(88))

	// using the same salt will ensure the hash is consistent to make sure hash generation is correct
	origReader := rand.Reader
	defer func() { rand.Reader = origReader }()
	salt, _ := encoding.DecodeString("test.using.known.salt.")
	rand.Reader = bytes.NewBuffer(salt)
	h, _ = DefaultHashPassword("a-password")
	g.Expect(h).Should(gomega.Equal("$argon2id19$1,65536,4$test.using.known.salt.$FzP8/LecDac/ywiH46nGLmtMM9skQaqKrttw/K9zp2."))
}

func TestHashPassword(t *testing.T) {
	g := gomega.NewGomegaWithT(t)

	h, _ := HashPassword("test2", 2, 32*1024, 2, 17)
	g.Expect(Compare(h, "test2")).Should(gomega.Succeed())
	g.Expect(Compare(h, "bad-password")).ShouldNot(gomega.Succeed())
	g.Expect(Compare(h, "bad-password")).Should(gomega.Equal(ErrMismatchedHashAndPassword))
	g.Expect(h).Should(gomega.MatchRegexp(`^\Q$argon2id19$2,32768,2$`))
	g.Expect(len(h)).Should(gomega.Equal(68))
}

func TestHashPasswordWithSaltError(t *testing.T) {
	origReader := rand.Reader
	defer func() { rand.Reader = origReader }()

	rand.Reader = bytes.NewBuffer([]byte("incomplete"))
	h, err := DefaultHashPassword("test")

	g := gomega.NewGomegaWithT(t)
	g.Expect(h).Should(gomega.Equal(""))
	g.Expect(err).Should(gomega.Equal(io.ErrUnexpectedEOF))
}

func TestIsHashedPassword(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	h, _ := DefaultHashPassword("test3")
	g.Expect(IsHashedPassword(h)).Should(gomega.BeTrue())
	g.Expect(IsHashedPassword("$argon2id,2,32768,2$bad")).Should(gomega.BeFalse())
}

func TestFailure(t *testing.T) {
	g := gomega.NewGomegaWithT(t)
	g.Expect(Compare("bad-hash", "test4")).Should(gomega.Equal(ErrInvalidHash))
	g.Expect(Compare("$argon2id99$1,65536,4$PWhquEXHn6p9NoOuQQVwHw$J2fO7RdTPYGdoBb52cyYVEMdprPkAa/2hny3n0tGNm4", "test4")).Should(gomega.Equal(ErrInvalidArgon2Version))
	g.Expect(Compare("$argon2id19$1,65536,4$a$J2fO7RdTPYGdoBb52cyYVEMdprPkAa/2hny3n0tGNm4", "test4")).Should(gomega.MatchError(base64.CorruptInputError(0)), "invalid salt")
	g.Expect(Compare("$argon2id19$1,65536,4$PWhquEXHn6p9NoOuQQVwHw$a", "test4")).Should(gomega.MatchError(base64.CorruptInputError(0)), "invalid hash")

	// bounds checking
	g.Expect(Compare("$argon2id19$0,65536,4$Oy7MSyjRTCTMTAzROSvSGO$QV5KGjrKZO6C.8St0T7HCTL0AvuCxgf5O.Okwj90a3a", "time too small")).Should(gomega.Equal(ErrInvalidComplexity))
	g.Expect(Compare("$argon2id19$4294967296,65536,4$Oy7MSyjRTCTMTAzROSvSGO$QV5KGjrKZO6C.8St0T7HCTL0AvuCxgf5O.Okwj90a3a", "time too large")).Should(gomega.Equal(ErrInvalidComplexity))
	g.Expect(Compare("$argon2id19$1,4294967296,4$Oy7MSyjRTCTMTAzROSvSGO$QV5KGjrKZO6C.8St0T7HCTL0AvuCxgf5O.Okwj90a3a", "memory too large")).Should(gomega.Equal(ErrInvalidComplexity))
	g.Expect(Compare("$argon2id19$1,65536,0$Oy7MSyjRTCTMTAzROSvSGO$QV5KGjrKZO6C.8St0T7HCTL0AvuCxgf5O.Okwj90a3a", "threads too low")).Should(gomega.Equal(ErrInvalidComplexity))
	g.Expect(Compare("$argon2id19$1,65536,256$Oy7MSyjRTCTMTAzROSvSGO$QV5KGjrKZO6C.8St0T7HCTL0AvuCxgf5O.Okwj90a3a", "threads too large")).Should(gomega.Equal(ErrInvalidComplexity))
}
