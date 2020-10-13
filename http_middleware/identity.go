package http_middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/ricecake/karma_chameleon/util"
)

type AccessToken struct {
	Issuer     string `json:"iss"` // Who issued it?
	UserCode   string `json:"sub"` // Who's it about?
	Expiration int64  `json:"exp"` // When does it expire?
	IssuedAt   int64  `json:"iat"` // When was it issued?
	Code       string `json:"jti"` // What should we call it?
	ClientId   string `json:"azp"` // What system was it given to?

	// Non-manditory fields MUST be "omitempty"
	Nonce          string    `json:"nonce,omitempty"` // Maybe have a random number
	ContextCode    string    `json:"ctx,omitempty"`   // What usage context is this from
	Scope          string    `json:"scope,omitempty"` // What level of access was requested
	Permitted      []string  `json:"perm,omitempty"`  // What can the subject do
	ValidResources *[]string `json:"aud,omitempty"`   // What resources are allowed to look at it.

	Browser  string `json:"bro,omitempty"` // What browser did it come from?
	Strength string `json:"acr,omitempty"` // How safe is it?
	Method   string `json:"amr,omitempty"` // How did they get it?
}

func NewAuthMiddleware(cacher util.VerifierCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Trace("Starting auth")
		headerParts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			log.Error("Malformed header")
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		var accesstToken AccessToken

		keys, revMap, cacheErr := cacher.Fetch()

		if cacheErr != nil {
			log.Error("Cache error: ", cacheErr)
			c.AbortWithError(500, errors.New("Internal Error")).SetType(gin.ErrorTypePublic)
			return
		}

		decErr := util.DecodeJWTOpenFromKeys(headerParts[1], keys, &accesstToken)
		if decErr != nil {
			log.Error("Bad token: ", decErr)
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		now := time.Now()
		if now.Unix() >= accesstToken.Expiration {
			log.Error("Expired token")
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		if !checkRevMap(revMap, accesstToken) {
			log.Error("revoked token")
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		// Possibly need to add a new tracking table for "Api clients", since those are the actual services making
		// use of the tokens, and not just holding them.  Could then track which clients need to use which services...
		// That could be neat...
		if accesstToken.ValidResources != nil {
			if util.Contains(*accesstToken.ValidResources, []string{viper.GetString("basic.code")}) {
				log.Error("Invalid token audience party")
				c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
				return
			}
		}

		// Need to load this information into the request context as well.
		c.Set("ValidAuth", true)
		c.Set("Identity", accesstToken.UserCode)
		c.Set("Token", accesstToken)
		c.Next()
	}
}

func checkRevMap(revMap *util.RevMap, token AccessToken) bool {
	checks := [][]string{
		{"ctx", token.ContextCode},
		{"bro", token.Browser},
		{"jti", token.Code},
		{"sub", token.UserCode},
		{"azp", token.ClientId},
	}

	for _, list := range checks {
		if revMap.Revoked(list[0], list[1], int(token.IssuedAt)) {
			return false
		}
	}

	return true
}

func AclChecks(required []string) gin.HandlerFunc {
	// This should do set intersection on the required list, and the list or real permissions
	// Need to validate if the perms list contains only relevant perms, or if it's all of them.
	// Would like to be able to not need to reference the client id in every permission list for every method
	// can just do "network.acl.read"/"write"
	// If follwoing the pattern of templating in query args, can filter the list of "needs template" outside of method, and merge
	// with the rest inside the method, after templating.
	return func(c *gin.Context) {
		tokenInt, _ := c.Get("Token")
		token := tokenInt.(AccessToken)
		if !util.Contains(token.Permitted, required) {
			c.AbortWithStatusJSON(401, required)
			return
		}
		c.Next()
	}
}
