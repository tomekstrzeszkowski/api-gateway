package main

import (
	"context"
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
	router.GET("/rsa-public", securityManager.EndpointExposePublicKey())
	// dynamic service registration
	router.POST("/register-services/all", func(c *gin.Context) {
		// basic echo service
		if err := api.RegisterEchoServiceWithRoutes(c); err != nil {
			return
		}
		// SSL
		if err := api.RegisterCertServiceWithRoutes(c); err != nil {
			return
		}
		// Custom E2E encryption
		if err := api.RegisterE2eServiceWithRoutes(c, router); err != nil {
			return
		}
		api.UpdateRouter(router)
		c.Status(http.StatusOK)
	})
	// add monitoring middleware and endpoints
	router.Use(resourceMonitor.GetMiddleware())
	resourceMonitor.SetupEndpoints(router)
	router.Run(":8080")
}
