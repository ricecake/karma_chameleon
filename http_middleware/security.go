package http_middleware

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"github.com/unrolled/secure"
)

func SecurityMiddleware() gin.HandlerFunc {
	var cspHeader string
	if viper.IsSet("security.csp") {
		for directive, values := range viper.GetStringMapStringSlice("security.csp") {
			setting := directive
			for _, value := range values {
				setting = setting + " " + value
			}
			cspHeader = cspHeader + setting + ";"
		}
	}

	secureMiddleware := secure.New(secure.Options{
		IsDevelopment:           viper.GetBool("development.insecure"),
		SSLRedirect:             !viper.GetBool("development.insecure"),
		SSLHost:                 viper.GetString("http.host"),
		STSSeconds:              viper.GetInt64("security.hsts"),
		SSLProxyHeaders:         map[string]string{"X-Forwarded-Proto": "https"},
		STSIncludeSubdomains:    true,
		STSPreload:              true,
		CustomFrameOptionsValue: "SAMEORIGIN",
		BrowserXssFilter:        true,
		ContentSecurityPolicy:   cspHeader,
	})
	return func(c *gin.Context) {
		log.Trace("Entering Security Middleware")
		defer log.Trace("Exiting Security Middleware")

		cspNonce, err := secureMiddleware.ProcessAndReturnNonce(c.Writer, c.Request)
		if err != nil {
			log.Error(err)
			c.AbortWithError(500, err).SetType(gin.ErrorTypePublic)
			return
		}

		c.Set("CspNonce", cspNonce)

		if c.Request.Method != "OPTIONS" {
			if status := c.Writer.Status(); status > 300 && status < 399 {
				log.Trace("Sec Middleware redirect")
				c.Abort()
				return
			}
		}

		origin := c.Request.Header.Get("Origin")
		if origin == "" {
			log.Trace("Sec Middleware no-origin")
			return
		}

		host := c.Request.Host
		// This should get set as log metadata once there are request contexts
		// log.Printf("Host: %s Origin: %s", host, origin)
		if origin == "http://"+host || origin == "https://"+host {
			log.Trace("Sec Middleware not cors")
			return
		}

		if c.ContentType() == "application/csp-report" && origin == viper.GetString("http.host") {
			buf := make([]byte, 1024)
			num, _ := c.Request.Body.Read(buf)
			reqBody := buf[0:num]

			var cspReport map[string]log.Fields
			jsonErr := json.Unmarshal(reqBody, &cspReport)
			if jsonErr != nil {
				log.Error(jsonErr)
			} else {
				log.WithFields(cspReport["csp-report"]).Warn("CSP Violation")
			}

			c.Status(204)
			return
		}

		var allow bool

		// Need to allow a way to pass a list of allowed origin.
		// if there is an allowed origin, and it matches, and there are now path restrictions,
		// allow.
		// if there are path restrictions, defer to those if the origin is allowed.
		// origin should allow wildcards.
		// should do something like "replace '*' with regex for single dns label, and then anchor"
		// If no origin is specified, then that origin is allowed.

		// This might be easiest split into standalone method, that can return if it concludes early.

		// if originAllowed {
		// 	if hasPathLimit {
		// 		if pathValid {
		// 			allow;
		// 		}
		// 	}
		// 	else {
		// 		allow;
		// 	}
		// }

		requestPath := c.Request.URL.Path
		for _, allowPath := range viper.GetStringSlice("security.cors.allow") {
			if requestPath == allowPath {
				allow = true
				break
			}
		}

		// Some paths are never allowed via cors
		for _, forbidPath := range viper.GetStringSlice("security.cors.forbid") {
			if strings.HasPrefix(requestPath, forbidPath) {
				log.WithFields(log.Fields{
					"request_url": requestPath,
					"prefix_rule": forbidPath,
				}).Error("CORS Policy expressly forbifs URL")
				allow = false
				break
			}
		}
		if !allow {
			c.AbortWithError(http.StatusForbidden, fmt.Errorf("Request not allowed by server configuration")).SetType(gin.ErrorTypePublic)
			return
		}

		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", c.Request.Header.Get("Access-Control-Request-Headers"))
		c.Header("Vary", "Origin")

		if c.Request.Method == "OPTIONS" {
			c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			c.Header("Access-Control-Max-Age", strconv.FormatInt(int64(12*time.Hour/time.Second), 10))

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
