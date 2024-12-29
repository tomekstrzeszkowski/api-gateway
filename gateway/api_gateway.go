package gateway

import (
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
