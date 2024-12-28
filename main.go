package main

import (
	"log"
	"net/http"

	"example.com/m/v2/gateway"
	"example.com/m/v2/security"
	"github.com/gin-gonic/gin"
)

func main() {
	api := gateway.NewAPIGateway()
	securityManager, _ := security.NewSecurityManager(nil, nil)
	router := api.InitializeRouter(securityManager)
	router.GET("/rsa-public", func(c *gin.Context) {
		publicKey, _ := securityManager.ExportPublicKey()
		c.JSON(http.StatusOK, gin.H{
			"public": string(publicKey),
		})
	})
	router.POST("/register-services/all", func(c *gin.Context) {
		echoService := &gateway.ServiceConfig{
			Name:    "echo",
			Scheme:  "http",
			BaseUrl: "echo-server:80",
		}
		if err := api.AddService(echoService); err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		api.AddRoute(gateway.Route{
			Path:        "/echo",
			ServiceName: echoService.Name,
			Methods:     []string{"GET", "POST"},
		})
		cert := "/external/cert.pem"
		skipVerify := false
		certService := &gateway.ServiceConfig{
			Name:                          "cert",
			Scheme:                        "https",
			BaseUrl:                       "cert-server:8001",
			Certificate:                   &cert,
			CertificateInsecureSkipVerify: &skipVerify,
		}
		if err := api.AddService(certService); err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		api.AddRoute(gateway.Route{
			Path:        "/cert",
			ServiceName: certService.Name,
			Methods:     []string{"POST"},
		})
		api.UpdateRouter(router)
		c.Status(http.StatusOK)
	})
	router.Run(":8080")
}
