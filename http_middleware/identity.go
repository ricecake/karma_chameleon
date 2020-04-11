package http_middleware

import (
	"errors"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/ricecake/karma_chameleon/util"
)

func NewAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Trace("Starting auth")
		headerParts := strings.SplitN(c.GetHeader("Authorization"), " ", 2)
		if len(headerParts) != 2 || strings.ToLower(headerParts[0]) != "bearer" {
			log.Error("Malformed header")
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		var jwtParts map[string]interface{}

		// Will need to add the ability to pass specific keys to DecodeJWTOpen.
		// Also need to check against the revocation list to make sure it's still good.
		// Revocation list, and key retrieval, should be parameterized, so that it can be re-used between projects.
		decErr := util.DecodeJWTOpen(headerParts[1], &jwtParts)
		if decErr != nil {
			log.Error("Bad token: ", decErr)
			c.AbortWithError(401, errors.New("Invalid authorization")).SetType(gin.ErrorTypePublic)
			return
		}

		c.Set("ValidAuth", true)
		c.Set("Identity", jwtParts["sub"].(string))
		c.Next()
	}
}
