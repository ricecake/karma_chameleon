package util

import (
	"bytes"
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
	"net/url"
	"time"

	"github.com/gorilla/http"
	"github.com/pborman/uuid"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/fresh8/go-cache/cacher"
	engine "github.com/fresh8/go-cache/engine/memory"
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

type RevMap *map[string]map[string]struct {
	CreatedAt string `json:"created_at"`
	ExpiresIn string `json:"expires_in"`
}

type VerifierCache interface {
	Fetch() (*jose.JSONWebKeySet, RevMap, error)
}

type IdpVerifierCache struct {
	engine *engine.Engine
	cacher cacher.Cacher
}

func NewIdpVerifierCache() (newCacher *IdpVerifierCache) {
	newCacher = &IdpVerifierCache{}
	newCacher.engine = engine.NewMemoryStore(15 * time.Second)
	newCacher.cacher = cacher.NewCacher(newCacher.engine, 10, 10)
	return newCacher
}

func (verifier *IdpVerifierCache) Fetch() (*jose.JSONWebKeySet, RevMap, error) {
	reqUrl, urlErr := url.Parse(viper.GetString("basic.auth"))

	if urlErr != nil {
		return nil, nil, urlErr
	}

	var keyBuf bytes.Buffer
	reqUrl.Path = "/publickeys"

	_, httpBufErr := http.Get(&keyBuf, reqUrl.String())
	if httpBufErr != nil {
		return nil, nil, httpBufErr
	}

	var revBuf bytes.Buffer
	reqUrl.Path = "/revocation"

	_, httpRevErr := http.Get(&revBuf, reqUrl.String())
	if httpRevErr != nil {
		return nil, nil, httpRevErr
	}

	var jwks jose.JSONWebKeySet
	jsonJwkErr := json.Unmarshal(keyBuf.Bytes(), &jwks)
	if jsonJwkErr != nil {
		return nil, nil, jsonJwkErr
	}

	var revMap RevMap
	jsonRevErr := json.Unmarshal(revBuf.Bytes(), &revMap)
	if jsonRevErr != nil {
		return nil, nil, jsonRevErr
	}

	return &jwks, revMap, nil
}
