package gateway

import (
	"context"
	"net/http/httputil"
	"time"

	"example.com/m/v2/security"
	"github.com/gin-gonic/gin"
)

type HandlerFunc func(c *gin.Context, sm *security.SecurityManager, serviceProxy *httputil.ReverseProxy)

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
	securityManager, err := security.NewSecurityManager(nil, certificate, certificateSkipVerify, nil)
	if err != nil {
		return nil, err
	}
	return &ServiceConfig{
		Name:            name,
		BaseUrl:         baseUrl,
		Scheme:          scheme,
		SecurityManager: securityManager,
		RouteHandler:    DefaultHandler,
	}, nil
}
func NewE2eEncryptedService(
	name string,
	baseUrl string,
	privateKey *string,
	publicKey *string,
	certificate *string,
	certificateSkipVerify *bool,
) (*ServiceConfig, error) {
	scheme := "http"
	if certificate != nil {
		scheme = "https"
	}
	securityManager, err := security.NewSecurityManager(
		privateKey, certificate, certificateSkipVerify, publicKey,
	)
	if err != nil {
		return nil, err
	}
	return &ServiceConfig{
		Name:            name,
		BaseUrl:         baseUrl,
		Scheme:          scheme,
		SecurityManager: securityManager,
		RouteHandler:    security.E2eEncryptionHandler,
	}, nil
}
func DefaultHandler(c *gin.Context, _ *security.SecurityManager, serviceProxy *httputil.ReverseProxy) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)

	serviceProxy.ServeHTTP(c.Writer, c.Request)
}
