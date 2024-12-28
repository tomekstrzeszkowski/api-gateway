# API Gateway
This project is for learning purposes. 
Key features:
 - Dynamic services registration
 - SSL support
 - Monitoring - TODO
 - E2E - TODO

# Debugging
create `docker.compose.override.yml`, see: `docker.compose.override.debugging.yml`,
```
docker compose up --bulid
```
Run IDE debugger

# Usage

## Register all services
```
curl -X POST localhost:8080/register-services/all
```
Test registered services
```
curl -X GET localhost:8080/echo
```
```
curl -X POST localhost:8080/cert -d "param1=value1&param2=value2"
```

example request:
```
curl localhost:8080/echo
```
# Examples

TODO: secure-server-todo.py
monitoring
```go
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	"github.com/shirou/gopsutil/v3/net"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// ResourceMonitor struktura do monitorowania zasobów systemu
type ResourceMonitor struct {
	logger           *zap.Logger
	mu               sync.RWMutex
	metricsHistory   map[string][]MetricEntry
	requestCounters  map[string]int
	errorCounters    map[string]int
	startTime        time.Time
	resourceThresholds ResourceThresholds
}

// MetricEntry reprezentuje single wpis metryki
type MetricEntry struct {
	Timestamp time.Time
	Value     float64
}

// ResourceThresholds definiuje progi alertów
type ResourceThresholds struct {
	CPUUsage     float64 `yaml:"cpu_usage"`
	MemoryUsage  float64 `yaml:"memory_usage"`
	DiskUsage    float64 `yaml:"disk_usage"`
	NetworkUsage float64 `yaml:"network_usage"`
}

// SystemMetrics przechowuje aktualne metryki systemowe
type SystemMetrics struct {
	CPUUsage       float64
	MemoryUsage    float64
	DiskUsage      float64
	NetworkUsage   float64
	GoroutineCount int
	Uptime         time.Duration
	RequestStats   map[string]int
	ErrorStats     map[string]int
}

// NewResourceMonitor tworzy nowy monitor zasobów
func NewResourceMonitor() *ResourceMonitor {
	logger, _ := zap.NewProduction()
	return &ResourceMonitor{
		logger:          logger,
		metricsHistory: make(map[string][]MetricEntry),
		requestCounters: make(map[string]int),
		errorCounters:   make(map[string]int),
		startTime:       time.Now(),
		resourceThresholds: ResourceThresholds{
			CPUUsage:     70.0,
			MemoryUsage:  80.0,
			DiskUsage:    90.0,
			NetworkUsage: 90.0,
		},
	}
}

// CollectSystemMetrics zbiera aktualne metryki systemowe
func (rm *ResourceMonitor) CollectSystemMetrics() (*SystemMetrics, error) {
	// CPU Usage
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}

	// Memory Usage
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	// Disk Usage
	diskStat, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}

	// Network Usage
	netIOCounters, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}

	// Calc network usage (bytes/sec)
	var networkUsage float64
	if len(netIOCounters) > 0 {
		networkUsage = float64(netIOCounters[0].BytesSent+netIOCounters[0].BytesRecv) / 1024 / 1024 // MB
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()

	metrics := &SystemMetrics{
		CPUUsage:       cpuPercent[0],
		MemoryUsage:    vmStat.UsedPercent,
		DiskUsage:      diskStat.UsedPercent,
		NetworkUsage:   networkUsage,
		GoroutineCount: runtime.NumGoroutine(),
		Uptime:         time.Since(rm.startTime),
		RequestStats:   rm.requestCounters,
		ErrorStats:     rm.errorCounters,
	}

	// Aktualizacja historii metryk
	rm.updateMetricsHistory(metrics)

	return metrics, nil
}

// updateMetricsHistory aktualizuje historię metryk
func (rm *ResourceMonitor) updateMetricsHistory(metrics *SystemMetrics) {
	now := time.Now()
	
	metricMap := map[string]float64{
		"cpu_usage":     metrics.CPUUsage,
		"memory_usage":  metrics.MemoryUsage,
		"disk_usage":    metrics.DiskUsage,
		"network_usage": metrics.NetworkUsage,
	}

	for metricName, value := range metricMap {
		rm.metricsHistory[metricName] = append(rm.metricsHistory[metricName], MetricEntry{
			Timestamp: now,
			Value:     value,
		})

		// Ogranicz historię do ostatnich 100 wpisów
		if len(rm.metricsHistory[metricName]) > 100 {
			rm.metricsHistory[metricName] = rm.metricsHistory[metricName][1:]
		}
	}
}

// CheckAlerts sprawdza czy któryś z progów został przekroczony
func (rm *ResourceMonitor) CheckAlerts(metrics *SystemMetrics) []string {
	var alerts []string

	if metrics.CPUUsage > rm.resourceThresholds.CPUUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: Wysokie użycie CPU (%.2f%%)", metrics.CPUUsage))
	}

	if metrics.MemoryUsage > rm.resourceThresholds.MemoryUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: Wysokie użycie pamięci (%.2f%%)", metrics.MemoryUsage))
	}

	if metrics.DiskUsage > rm.resourceThresholds.DiskUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: Wysokie użycie dysku (%.2f%%)", metrics.DiskUsage))
	}

	if metrics.NetworkUsage > rm.resourceThresholds.NetworkUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: Wysokie użycie sieci (%.2f MB/s)", metrics.NetworkUsage))
	}

	return alerts
}

// MonitoringMiddleware middleware do zliczania requestów
func (rm *ResourceMonitor) MonitoringMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rm.mu.Lock()
		rm.requestCounters[c.Request.Method]++
		rm.mu.Unlock()

		c.Next()

		// Zliczanie błędów
		if c.Writer.Status() >= 400 {
			rm.mu.Lock()
			rm.errorCounters[c.Request.Method]++
			rm.mu.Unlock()
		}
	}
}

// SetupMonitoringEndpoints konfiguruje endpointy monitoringu
func (rm *ResourceMonitor) SetupMonitoringEndpoints(r *gin.Engine) {
	// Endpoint metryk systemowych
	r.GET("/metrics", func(c *gin.Context) {
		metrics, err := rm.CollectSystemMetrics()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		alerts := rm.CheckAlerts(metrics)

		c.JSON(http.StatusOK, gin.H{
			"metrics": metrics,
			"alerts":  alerts,
		})
	})

	// Endpoint historii metryk
	r.GET("/metrics-history", func(c *gin.Context) {
		rm.mu.RLock()
		defer rm.mu.RUnlock()
		c.JSON(http.StatusOK, rm.metricsHistory)
	})
}

// StartPeriodicMonitoring uruchamia periodyczny monitoring w tle
func (rm *ResourceMonitor) StartPeriodicMonitoring(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			metrics, err := rm.CollectSystemMetrics()
			if err != nil {
				rm.logger.Error("Błąd pobierania metryk", zap.Error(err))
				continue
			}

			alerts := rm.CheckAlerts(metrics)
			if len(alerts) > 0 {
				for _, alert := range alerts {
					rm.logger.Warn(alert)
				}
			}
		}
	}
}

func main() {
	// Inicjalizacja monitora
	resourceMonitor := NewResourceMonitor()

	// Kontekst dla monitoringu w tle
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Uruchomienie monitoringu w tle
	go resourceMonitor.StartPeriodicMonitoring(ctx)

	// Konfiguracja routera
	r := gin.Default()

	// Dodanie middleware monitoringu
	r.Use(resourceMonitor.MonitoringMiddleware())

	// Dodanie endpointów monitoringu
	resourceMonitor.SetupMonitoringEndpoints(r)

	// Uruchomienie serwera
	r.Run(":8080")
}

```

More Examples:
```
curl localhost:8080/rsa-public
```
```
curl localhost:8080/echo -H "X-Encrypted-Request: fail"
```