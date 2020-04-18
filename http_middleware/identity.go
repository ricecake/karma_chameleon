package http_middleware

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/ricecake/karma_chameleon/util"
)

type AccessToken struct {
	Issuer     string `json:"iss"`
	UserCode   string `json:"sub"`
	Expiration int64  `json:"exp"`
	IssuedAt   int64  `json:"iat"`
	Code       string `json:"jti"`
	ClientId   string `json:"azp"`

	Nonce         string   `json:"nonce,omitempty"` // Non-manditory fields MUST be "omitempty"
	ValidResource string   `json:"aud,omitempty"`
	ContextCode   string   `json:"ctx,omitempty"`
	Scope         string   `json:"scope,omitempty"`
	Permitted     []string `json:"perm,omitempty"`

	Browser  string `json:"bro,omitempty"`
	Strength string `json:"acr,omitempty"`
	Method   string `json:"amr,omitempty"`
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

		// Will need to add the ability to pass specific keys to DecodeJWTOpen.
		// Also need to check against the revocation list to make sure it's still good.
		// Revocation list, and key retrieval, should be parameterized, so that it can be re-used between projects.
		keys, _, cacheErr := cacher.Fetch()

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

		// This is too naive.  Need to be setting the azp field to all of the clients that the sub
		// has access to, in an array, and the checking that we're in that list.
		// Possibly need to add a new tracking table for "Api clients", since those are the actual services making
		// use of the tokens, and not just holding them.  Could then track which clients need to use which services...
		// That could be neat...
		// if accesstToken.ClientId != viper.GetString("basic.code") {
		// 	log.Error("Invalid token authorized party: ", accesstToken.ClientId)
		// 	c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
		// 	return
		// }

		c.Set("ValidAuth", true)
		c.Set("Identity", accesstToken.UserCode)
		c.Set("Token", accesstToken)
		c.Next()
	}
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
