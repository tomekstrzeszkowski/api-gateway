package gateway

import (
	"bytes"
	"context"
	"io"
	"strconv"
	"time"

	"example.com/m/v2/security"
	"github.com/gin-gonic/gin"
)

type HandlerFunc func(c *gin.Context, sm *security.SecurityManager) context.CancelFunc

type ServiceConfig struct {
	Name            string
	BaseUrl         string
	Scheme          string
	SecurityManager *security.SecurityManager
	RouteHandler    HandlerFunc
}

func NewService(
	name string, baseUrl string, certificate *string, certificateSkipVerify *bool,
) (*ServiceConfig, error) {
	scheme := "http"
	if certificate != nil {
		scheme = "https"
	}
	securityManager, err := security.NewSecurityManager(nil, certificate, certificateSkipVerify)
	if err != nil {
		return nil, err
	}
	return &ServiceConfig{
		Name:            name,
		BaseUrl:         baseUrl,
		Scheme:          scheme,
		SecurityManager: securityManager,
		RouteHandler:    BasicHandler,
	}, nil
}
func NewE2eEncryptedService(name string, baseUrl string, privateKey *string, certificate *string, certificateSkipVerify *bool) (*ServiceConfig, error) {
	scheme := "http"
	if certificate != nil {
		scheme = "https"
	}
	securityManager, err := security.NewSecurityManager(privateKey, certificate, certificateSkipVerify)
	if err != nil {
		return nil, err
	}
	return &ServiceConfig{
		Name:            name,
		BaseUrl:         baseUrl,
		Scheme:          scheme,
		SecurityManager: securityManager,
		RouteHandler:    E2eEncryptionHandler,
	}, nil
}
func BasicHandler(c *gin.Context, _ *security.SecurityManager) context.CancelFunc {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	c.Request = c.Request.WithContext(ctx)
	return cancel
}
func E2eEncryptionHandler(c *gin.Context, sm *security.SecurityManager) context.CancelFunc {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	c.Request = c.Request.WithContext(ctx)

	contentLength := c.Request.ContentLength
	if contentLength < 1 {
		return cancel
	}
	bodyBytes := make([]byte, contentLength)
	_, err := io.ReadFull(c.Request.Body, bodyBytes)
	if err != nil {
		c.Request.Header.Set("Content-Length", "0")
		c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte{}))
		return cancel
	}
	encryptedBody, err := sm.EncryptRSA(bodyBytes)
	if err != nil {
		c.Request.Header.Set("Content-Length", "0")
		c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte{}))
		return cancel
	}
	encryptedBytes := []byte(encryptedBody)
	c.Request.ContentLength = int64(len(encryptedBytes))
	c.Request.Header.Set("Content-Length", strconv.Itoa(len(encryptedBytes)))
	c.Request.Body = io.NopCloser(bytes.NewBuffer(encryptedBytes))

	return cancel
}
