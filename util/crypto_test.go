package util_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/ricecake/karma_chameleon/util"
)

var _ = Describe("Crypto related functions", func() {
	Describe("CompactUUID method", func() {
		uuid := util.CompactUUID()
		It("returns a well-formed string", func() {
			Expect(uuid).NotTo(Equal(""))
			Expect(uuid).To(MatchRegexp("^[A-Za-z0-9+_-]+$"))
		})
	})
	Describe("hashing routines", func() {
		hashData := []byte("Sensitive Data")
		Describe("PasswordHash method", func() {
			It("does not error", func() {
				_, err := util.PasswordHash(hashData)
				Expect(err).To(BeNil())
			})
			It("produces expected output", func() {
				hash, _ := util.PasswordHash(hashData)
				Expect(hash).To(MatchRegexp("^\\$\\w{2}\\$10\\$(\\S+)+$"))
			})
		})
		Describe("PasswordHashValid method", func() {
			It("Validates correct password", func() {
				hash, _ := util.PasswordHash(hashData)
				Expect(util.PasswordHashValid(hashData, hash)).To(BeTrue())
			})
			It("rejects wrong password", func() {
				hash, _ := util.PasswordHash(hashData)
				Expect(util.PasswordHashValid([]byte("Wrong"), hash)).To(BeFalse())
			})
		})
		Describe("DeriveKey method", func() {
			It("Produces expected length output", func() {
				Expect(len(util.DeriveKey("password"))).To(Equal(32))
			})
			It("Produces consistent output", func() {
				Expect(util.DeriveKey("password")).To(Equal(util.DeriveKey("password")))
			})
		})
	})
	Describe("encryption routines", func() {
		Describe("Encrypt method", func() {
			It("does not error", func() {
				_, err := util.Encrypt("Test", []byte("Cats are good"))
				Expect(err).To(BeNil())
			})
		})
		Describe("Decrypt method", func() {
			It("does not error", func() {
				cipherText, _ := util.Encrypt("Test", []byte("Cats are good"))
				_, err := util.Decrypt("Test", cipherText)
				Expect(err).To(BeNil())
			})
		})
		It("is reversible", func() {
			input := []byte("Cats are good")
			cipherText, _ := util.Encrypt("Test", input)
			output, _ := util.Decrypt("Test", cipherText)
			Expect(output).To(Equal(input))
		})
	})
})
