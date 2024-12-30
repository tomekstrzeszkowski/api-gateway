package main

import (
	"context"
	"log"
	"net/http"

	"example.com/m/v2/gateway"
	"example.com/m/v2/monitoring"
	"example.com/m/v2/security"
	"github.com/gin-gonic/gin"
)

func main() {
	api := gateway.NewAPIGateway()
	// global security manager, each service has its own too
	securityManager, _ := security.NewSecurityManager(nil, nil, nil, nil)
	// monitor resource in background
	resourceMonitor, _ := monitoring.NewResourceMonitor()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go resourceMonitor.StartPeriodicMonitoring(ctx)
	router := api.InitializeRouter(securityManager)
	// expose rsa public key just for learning purposes,
	// it's recommended to remove this endpint for any other use
	router.GET("/rsa-public", func(c *gin.Context) {
		publicKey, _ := securityManager.ExportPublicKey()
		c.JSON(http.StatusOK, gin.H{
			"public": string(publicKey),
		})
	})
	// dynamic service registration
	router.POST("/register-services/all", func(c *gin.Context) {
		// basic echo service
		echoService, err := gateway.NewService("echo", "echo-server:80", nil, nil)
		if err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		if err := api.AddService(echoService); err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		api.AddRoute(&gateway.Route{
			Path:        "/echo",
			ServiceName: echoService.Name,
			Methods:     []string{"GET", "POST"},
		})
		// SSL
		cert := "/secr/cert.pem"
		skipVerify := false
		certService, err := gateway.NewService("cert", "cert-server:8001", &cert, &skipVerify)
		if err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		if err := api.AddService(certService); err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		api.AddRoute(&gateway.Route{
			Path:        "/cert",
			ServiceName: certService.Name,
			Methods:     []string{"POST"},
		})
		// Custom E2E encryption
		privateKey := "/secr/gateway/private.key"
		publicKey := "/secr/public.pem"
		encryptedService, err := gateway.NewE2eEncryptedService(
			"encrypted", "encrypted-server:8011", &privateKey, &publicKey, nil, nil,
		)
		if err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		if err := api.AddService(encryptedService); err != nil {
			log.Fatalf("Service adding error %v", err)
		}
		api.AddRoute(&gateway.Route{
			Path:        "/e2e",
			ServiceName: encryptedService.Name,
			Methods:     []string{"POST"},
		})
		api.UpdateRouter(router)
		c.Status(http.StatusOK)
	})
	// add monitoring middleware and endpoints
	router.Use(resourceMonitor.GetMiddleware())
	resourceMonitor.SetupEndpoints(router)
	router.Run(":8080")
}
