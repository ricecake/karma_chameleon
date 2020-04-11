package http_middleware

import (
	"log"

	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"github.com/ulule/limiter/v3"
	ginAdapter "github.com/ulule/limiter/v3/drivers/middleware/gin"
	memStore "github.com/ulule/limiter/v3/drivers/store/memory"

	"github.com/ricecake/karma_chameleon/util"
	// "context"
)

func NewEnvMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("Reqid", util.CompactUUID())
		c.Next()
	}
}

func RateLimiter() gin.HandlerFunc {
	ratelimit := viper.GetString("ratelimit")
	rate, err := limiter.NewRateFromFormatted(ratelimit)
	if err != nil {
		log.Fatal(err)
	}
	store := memStore.NewStore()
	return ginAdapter.NewMiddleware(limiter.New(store, rate))
}
