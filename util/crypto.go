package util

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/pborman/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Hashing, encrypting, and strong random generation

var (
	Signer jose.Signer
	Keys   *jose.JSONWebKeySet
)

func PasswordHash(plaintext []byte) ([]byte, error) {
	ciphertext, err := bcrypt.GenerateFromPassword(plaintext, 10)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func PasswordHashValid(plaintext, hash []byte) bool {
	err := bcrypt.CompareHashAndPassword(hash, plaintext)

	return err == nil
}

func CompactUUID() string {
	return base64.RawURLEncoding.EncodeToString([]byte(uuid.NewRandom()))
}

func Encrypt(passphrase string, plaintext []byte) ([]byte, error) {
	key := DeriveKey(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

func Decrypt(passphrase string, ciphertext []byte) ([]byte, error) {
	key := DeriveKey(passphrase)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := aesgcm.Open(nil, ciphertext[:aesgcm.NonceSize()], ciphertext[aesgcm.NonceSize():], nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func EncodeJWTOpen(tok interface{}) (string, error) {
	raw, err := jwt.Signed(Signer).Claims(tok).CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

func DecodeJWTOpen(raw string, decoded interface{}) error {
	return DecodeJWTOpenFromKeys(raw, Keys, decoded)
}

func DecodeJWTOpenFromKeys(raw string, keys *jose.JSONWebKeySet, decoded interface{}) error {
	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return err
	}
	return tok.Claims(keys, decoded)
}

func EncodeJWTClose(tok interface{}, passphrase string) (string, error) {
	key := DeriveKey(passphrase)
	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		jose.Recipient{
			Algorithm: jose.DIRECT,
			Key:       key,
		},
		(&jose.EncrypterOptions{}).WithType("JWT").WithContentType("JWT"),
	)
	if err != nil {
		return "", err
	}

	raw, err := jwt.SignedAndEncrypted(Signer, enc).Claims(tok).CompactSerialize()
	if err != nil {
		return "", err
	}
	return raw, nil
}

func DecodeJWTClose(raw, passphrase string, decoded interface{}) error {
	key := DeriveKey(passphrase)
	tok, err := jwt.ParseSignedAndEncrypted(raw)
	if err != nil {
		return err
	}
	nested, err := tok.Decrypt(key)
	if err != nil {
		return err
	}
	return nested.Claims(Keys, decoded)
}

func DeriveKey(passphrase string) []byte {
	// Salt chosen at random, only used for start of key stretching
	return pbkdf2.Key([]byte(passphrase), []byte("0b131f2dc50d836216e2f25453cd012b131cd773"), 100, 32, sha3.New256)
}

func LoadKey(keyFile string) error {
	keyData, keyFileErr := ioutil.ReadFile(keyFile)
	if keyFileErr != nil {
		return keyFileErr
	}

	// Load signing key.
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("no private key found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}

	hash := CompactHash(block.Bytes)
	// Configure jwtSigner and public keys.
	privateKey := &jose.JSONWebKey{
		Key:       key,
		Algorithm: "RS256",
		Use:       "sig",
		KeyID:     hash,
	}

	Signer, err = jose.NewSigner(jose.SigningKey{
		Algorithm: jose.RS256,
		Key:       privateKey,
	}, nil)
	if err != nil {
		return err
	}
	Keys = &jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			jose.JSONWebKey{Key: &key.PublicKey,
				Algorithm: "RS256",
				Use:       "sig",
				KeyID:     hash,
			},
		},
	}
	return nil
}

func CompactHash(data []byte) string {
	hash := sha3.Sum256(data)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

type RevMap struct {
	cache map[string]map[string]struct {
		CreatedAt int `json:"created_at"`
		ExpiresIn int `json:"expires_in"`
	}
}

func NewRevMap() *RevMap {
	rev := &RevMap{}
	rev.cache = make(map[string]map[string]struct {
		CreatedAt int "json:\"created_at\""
		ExpiresIn int "json:\"expires_in\""
	})
	return rev
}

func (rev *RevMap) Add(field, key string, created, duration int) {
	revMap := rev.cache
	typeMap, ok := revMap[field]
	if !ok {
		typeMap = make(map[string]struct {
			CreatedAt int `json:"created_at"`
			ExpiresIn int `json:"expires_in"`
		})
		revMap[field] = typeMap
	}
	typeMap[key] = struct {
		CreatedAt int `json:"created_at"`
		ExpiresIn int `json:"expires_in"`
	}{
		CreatedAt: created,
		ExpiresIn: duration,
	}
}

func (rev *RevMap) Revoked(field, key string, issued int) bool {
	// TODO: This should acceppt an issued time, and allow the field if it was
	//       issued after the revocation was entered.
	if fieldKeys, found := rev.cache[field]; found {
		if entry, found := fieldKeys[key]; found {
			return entry.CreatedAt >= issued
		}
		return false
	}
	return false
}

type VerifierCache interface {
	Fetch() (*jose.JSONWebKeySet, *RevMap, error)
}

type IdpVerifierCache struct {
	keyCache *Cacher
	revCache *Cacher
}

func NewIdpVerifierCache() (newCacher *IdpVerifierCache) {
	newCacher = &IdpVerifierCache{}

	newCacher.keyCache = NewCacher(60*time.Second, func() (interface{}, error) {
		reqUrl, urlErr := url.Parse(viper.GetString("basic.auth"))
		if urlErr != nil {
			log.Error(urlErr)
			return nil, urlErr
		}
		reqUrl.Path = "/publickeys"
		body, getErr := get(reqUrl.String())
		if getErr != nil {
			log.Error(urlErr)
			return nil, getErr
		}

		var jwks jose.JSONWebKeySet
		jsonJwkErr := json.Unmarshal(body, &jwks)
		if jsonJwkErr != nil {
			return nil, jsonJwkErr
		}

		return &jwks, nil
	})

	newCacher.revCache = NewCacher(60*time.Second, func() (interface{}, error) {
		reqUrl, urlErr := url.Parse(viper.GetString("basic.auth"))
		if urlErr != nil {
			log.Error(urlErr)
			return nil, urlErr
		}
		reqUrl.Path = "/revocation"
		body, getErr := get(reqUrl.String())
		if getErr != nil {
			log.Error(urlErr)
			return nil, getErr
		}

		var revMap RevMap
		jsonRevErr := json.Unmarshal(body, &revMap)
		if jsonRevErr != nil {
			return nil, jsonRevErr
		}

		return &revMap, nil
	})

	return newCacher
}

func (verifier *IdpVerifierCache) Fetch() (*jose.JSONWebKeySet, *RevMap, error) {
	keys, err := verifier.keyCache.Fetch()
	revs, err := verifier.revCache.Fetch()

	return keys.(*jose.JSONWebKeySet), revs.(*RevMap), err
}

func get(url string) (body []byte, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	return ioutil.ReadAll(resp.Body)
}
