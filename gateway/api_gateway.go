package gateway

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"

	"example.com/m/v2/security"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type APIGateway struct {
	services      map[string]*ServiceConfig
	routes        []Route
	logger        *zap.Logger
	mu            sync.RWMutex
	activeProxies map[string]*httputil.ReverseProxy
}

func NewAPIGateway() *APIGateway {
	logger, _ := zap.NewProduction()
	return &APIGateway{
		services:      make(map[string]*ServiceConfig),
		routes:        []Route{},
		logger:        logger,
		activeProxies: make(map[string]*httputil.ReverseProxy),
	}
}

func (gw *APIGateway) AddService(service *ServiceConfig) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	_, err := url.Parse(service.BaseUrl)
	if err != nil {
		return fmt.Errorf("invalid URL %v", err)
	}
	proxy := httputil.NewSingleHostReverseProxy(&url.URL{
		Scheme: service.Scheme,
		Host:   service.BaseUrl,
	})
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		gw.logger.Error("Proxy Error", zap.String("service", service.Name), zap.Error(err))
		http.Error(w, "Service Error", http.StatusServiceUnavailable)
	}
	if service.SecurityManager.Certificate != nil {
		proxy.Transport = &http.Transport{
			TLSClientConfig: service.SecurityManager.GetTlsConfig(),
		}
	}
	gw.services[service.Name] = service
	gw.activeProxies[service.Name] = proxy
	return nil
}

func (gw *APIGateway) AddRoute(route *Route) error {
	gw.mu.Lock()
	defer gw.mu.Unlock()
	if _, exists := gw.services[route.ServiceName]; !exists {
		return fmt.Errorf("service %s does not exist", route.ServiceName)
	}
	route.Ready = false
	gw.routes = append(gw.routes, *route)
	return nil
}

func (gw *APIGateway) InitializeRouter(securityManager *security.SecurityManager) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	r.Use(securityManager.MiddlewareEncryption())
	return r
}

func (gw *APIGateway) UpdateRouter(r *gin.Engine) {
	for _, route := range gw.routes {
		if route.Ready {
			continue
		}
		serviceProxy, exists := gw.activeProxies[route.ServiceName]
		if !exists {
			gw.logger.Error("Couldn not find proxy", zap.String("service", route.ServiceName))
			continue
		}
		service := gw.services[route.ServiceName]
		for _, method := range route.Methods {
			r.Handle(method, route.Path, func(c *gin.Context) {
				service.RouteHandler(c, service.SecurityManager, serviceProxy)
			})
		}
		route.Ready = true
	}
}

func (gw *APIGateway) RegisterEchoServiceWithRoutes(c *gin.Context) error {
	echoService, _ := NewService("echo", "echo-server:80", nil, nil)
	err := gw.AddServiceWithRoutes(echoService, &[]*Route{
		&Route{
			Path:        "/echo",
			ServiceName: echoService.Name,
			Methods:     []string{"GET", "POST"},
		},
	})
	if err != nil {
		gw.logger.Error(fmt.Sprintf("%v", err))
		c.Abort()
	}
	return err
}

func (gw *APIGateway) RegisterCertServiceWithRoutes(c *gin.Context) error {
	cert := "/secr/cert.pem"
	skipVerify := false
	certService, _ := NewService("cert", "cert-server:8001", &cert, &skipVerify)
	err := gw.AddServiceWithRoutes(certService, &[]*Route{&Route{
		Path:        "/cert",
		ServiceName: certService.Name,
		Methods:     []string{"POST"},
	}})
	if err != nil {
		gw.logger.Error(fmt.Sprintf("%v", err))
		c.Abort()
	}
	return err
}

func (gw *APIGateway) RegisterE2eServiceWithRoutes(c *gin.Context, router *gin.Engine) error {
	privateKey := "/secr/gateway/private.key"
	publicKey := "/secr/public.pem"
	encryptedService, _ := NewE2eEncryptedService(
		"encrypted", "encrypted-server:8011", &privateKey, &publicKey, nil, nil,
	)
	route := Route{
		Path:        "/e2e",
		ServiceName: encryptedService.Name,
		Methods:     []string{"POST"},
	}
	err := gw.AddServiceWithRoutes(encryptedService, &[]*Route{&route})
	if err != nil {
		gw.logger.Error(fmt.Sprintf("%v", err))
		c.Abort()
	} else {
		router.GET(
			fmt.Sprintf("/rsa-public%s", route.Path),
			encryptedService.SecurityManager.EndpointExposePublicKey(),
		)
	}

	return err
}

func (gw *APIGateway) AddServiceWithRoutes(service *ServiceConfig, routes *[]*Route) error {
	if service == nil {
		gw.logger.Sugar().Fatalf("Service adding error")
		return errors.New("Service adding error")
	}
	if err := gw.AddService(service); err != nil {
		gw.logger.Sugar().Fatalf("Service adding error %v", err)
		return fmt.Errorf("Service `%s` adding error %v", service.Name, err)
	}
	for _, route := range *routes {
		err := gw.AddRoute(route)
		if err != nil {
			gw.logger.Sugar().Fatalf("Route adding error %v", err)
			return fmt.Errorf("Route `%s` adding error %v", route.Path, err)
		}
	}
	return nil
}
