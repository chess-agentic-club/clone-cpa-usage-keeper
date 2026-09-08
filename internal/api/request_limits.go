package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	unauthenticatedLoginBodyLimit   int64 = 4 << 10
	unauthenticatedLoginReadTimeout       = 15 * time.Second
)

func unauthenticatedLoginRequestLimits(basePath string) gin.HandlerFunc {
	prefix := strings.TrimSuffix(basePath, "/") + "/api/v1/auth/"
	loginPath := prefix + "login"
	apiKeyLoginPath := prefix + "api-key-login"
	ssoExchangePath := prefix + "sso/exchange"
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodPost || (c.Request.URL.Path != loginPath && c.Request.URL.Path != apiKeyLoginPath && c.Request.URL.Path != ssoExchangePath) {
			c.Next()
			return
		}

		// 匿名登录入口先建立读取期限，保证后续校验提前返回或关闭 body 时仍有时间上限。
		controller := http.NewResponseController(c.Writer)
		deadlineSet := controller.SetReadDeadline(time.Now().Add(unauthenticatedLoginReadTimeout)) == nil
		redactBody := c.Request.URL.Path == ssoExchangePath
		defer func() {
			if c.Request.Body != nil {
				_ = c.Request.Body.Close()
			}
			if redactBody {
				redactExchangeRequest(c.Request)
			}
			if deadlineSet {
				_ = controller.SetReadDeadline(time.Time{})
			}
		}()

		if c.Request.ContentLength > unauthenticatedLoginBodyLimit {
			writeRequestEntityTooLarge(c)
			c.Abort()
			return
		}
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, unauthenticatedLoginBodyLimit)
		}

		c.Next()
	}
}

func isRequestEntityTooLarge(err error) bool {
	var maxBytesError *http.MaxBytesError
	return errors.As(err, &maxBytesError)
}

func writeRequestEntityTooLarge(c *gin.Context) {
	c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "request body too large"})
}
