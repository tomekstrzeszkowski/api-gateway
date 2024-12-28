package monitoring

import (
	"context"
	"fmt"
	"net/http"
	"runtime"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
	"go.uber.org/zap"
)

type ResourceMonitor struct {
	logger            *zap.Logger
	mu                sync.RWMutex
	metricsHistory    map[string][]MetricEntry
	requestCounter    map[string]int
	errorCounter      map[string]int
	startTime         time.Time
	resourceThreshold ResourceTreshold
}

type MetricEntry struct {
	Timestamp time.Time
	Value     float64
}

type ResourceTreshold struct {
	CPUUsage     float64 `yaml:"cpu_usage"`
	MemoryUsage  float64 `yaml:"mamory_usage"`
	DiskUsage    float64 `yaml:"disk_usage"`
	NetworkUsage float64 `yaml:"network_usage"`
}

type SystemMetric struct {
	CPUUsage       float64
	MemoryUsage    float64
	DiskUsage      float64
	NetworkUsage   float64
	GoroutineCount int
	Uptime         time.Duration
	RequestStat    map[string]int
	ErrorStat      map[string]int
}

func NewResourceMonitor() (*ResourceMonitor, error) {
	logger, err := zap.NewProduction()
	if err != nil {
		return nil, err
	}
	return &ResourceMonitor{
		logger:         logger,
		metricsHistory: make(map[string][]MetricEntry),
		requestCounter: make(map[string]int),
		errorCounter:   make(map[string]int),
		startTime:      time.Now(),
		resourceThreshold: ResourceTreshold{
			CPUUsage:     70.0,
			MemoryUsage:  20.0,
			DiskUsage:    50.0,
			NetworkUsage: 10.0,
		},
	}, nil
}

func (rm *ResourceMonitor) CollectSystemMetric() (*SystemMetric, error) {
	cpuPercent, err := cpu.Percent(time.Second, false)
	if err != nil {
		return nil, err
	}

	vmMem, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}
	diskStat, err := disk.Usage("/")
	if err != nil {
		return nil, err
	}
	netIOCounters, err := net.IOCounters(false)
	if err != nil {
		return nil, err
	}
	var networkUsage float64
	if len(netIOCounters) > 0 {
		networkUsage = float64(netIOCounters[0].BytesSent+netIOCounters[0].BytesRecv) / 1024 / 1024 // MB
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	metric := &SystemMetric{
		CPUUsage:       cpuPercent[0],
		MemoryUsage:    vmMem.UsedPercent,
		DiskUsage:      diskStat.UsedPercent,
		NetworkUsage:   networkUsage,
		GoroutineCount: runtime.NumGoroutine(),
		ErrorStat:      rm.errorCounter,
		RequestStat:    rm.requestCounter,
	}
	rm.updateMetricHistory(metric)
	return metric, nil
}

func (rm *ResourceMonitor) updateMetricHistory(metric *SystemMetric) {
	now := time.Now()
	rm.metricsHistory["cpu"] = append(rm.metricsHistory["cpu"], MetricEntry{
		Timestamp: now,
		Value:     metric.CPUUsage,
	})

	rm.metricsHistory["memory"] = append(rm.metricsHistory["memory"], MetricEntry{
		Timestamp: now,
		Value:     metric.MemoryUsage,
	})
	rm.metricsHistory["disk"] = append(rm.metricsHistory["disk"], MetricEntry{
		Timestamp: now,
		Value:     metric.DiskUsage,
	})
	rm.metricsHistory["network"] = append(rm.metricsHistory["network"], MetricEntry{
		Timestamp: now,
		Value:     metric.NetworkUsage,
	})
	if len(rm.metricsHistory["cpu"]) > 1000 {
		rm.metricsHistory["cpu"] = rm.metricsHistory["cpu"][1:]
	}
	if len(rm.metricsHistory["memory"]) > 1000 {
		rm.metricsHistory["memory"] = rm.metricsHistory["memory"][1:]
	}
	if len(rm.metricsHistory["disk"]) > 1000 {
		rm.metricsHistory["disk"] = rm.metricsHistory["disk"][1:]
	}
	if len(rm.metricsHistory["network"]) > 1000 {
		rm.metricsHistory["network"] = rm.metricsHistory["network"][1:]
	}
}

func (rm *ResourceMonitor) CheckAlerts(metric *SystemMetric) []string {
	var alerts []string
	if metric.CPUUsage > rm.resourceThreshold.CPUUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: High CPU usage (%.2f%%)", metric.CPUUsage))
	}
	if metric.MemoryUsage > rm.resourceThreshold.MemoryUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: High Memory usage (%.2f%%)", metric.MemoryUsage))
	}
	if metric.DiskUsage > rm.resourceThreshold.DiskUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: High Disk usage (%.2f%%)", metric.DiskUsage))
	}
	if metric.NetworkUsage > rm.resourceThreshold.NetworkUsage {
		alerts = append(alerts, fmt.Sprintf("ALERT: High Network usage (%.2f%%)", metric.NetworkUsage))
	}
	return alerts
}
func (rm *ResourceMonitor) GetMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		rm.mu.Lock()
		rm.requestCounter[c.Request.RequestURI]++
		rm.mu.Unlock()
		c.Next()
		if c.Writer.Status() >= http.StatusBadRequest {
			rm.mu.Lock()
			rm.errorCounter[c.Request.RequestURI]++
			rm.mu.Unlock()
		}
	}
}

func (rm *ResourceMonitor) SetupEndpoints(r *gin.Engine) {
	r.GET("/metrics", func(c *gin.Context) {
		metric, err := rm.CollectSystemMetric()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		alerts := rm.CheckAlerts(metric)
		c.JSON(http.StatusOK, gin.H{
			"metric": metric,
			"alerts": alerts,
		})
	})
	r.GET("/metrics-history", func(c *gin.Context) {
		rm.mu.Lock()
		defer rm.mu.Unlock()
		c.JSON(http.StatusOK, rm.metricsHistory)
	})
}

func (rm *ResourceMonitor) StartPeriodicMonitoring(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			metric, err := rm.CollectSystemMetric()
			if err != nil {
				rm.logger.Error("Can not collect metric", zap.Error(err))
				continue
			}
			alerts := rm.CheckAlerts(metric)
			if len(alerts) > 0 {
				for _, alert := range alerts {
					rm.logger.Warn(alert)
				}
			}
		}
	}
}
