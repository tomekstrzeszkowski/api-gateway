package monitoring

import (
	"context"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

type MockResourceMonitor struct {
	*ResourceMonitor
	collectCalled int
	mu            sync.Mutex
}

const tickerOffset = 100

func NewMockResourceMonitor(t *testing.T) *MockResourceMonitor {
	logger := zaptest.NewLogger(t)
	return &MockResourceMonitor{
		ResourceMonitor: &ResourceMonitor{
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
		},
	}
}

func (m *MockResourceMonitor) CollectSystemMetric() (*SystemMetric, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.collectCalled++
	metric := &SystemMetric{
		CPUUsage:    80.0,
		MemoryUsage: 90.0,
		DiskUsage:   70.0,
	}
	m.updateMetricHistory(metric)
	return metric, nil
}

func (m *MockResourceMonitor) StartPeriodicMonitoring(ctx context.Context) {
	ticker := time.NewTicker(tickerOffset * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			metric, err := m.CollectSystemMetric()
			if err != nil {
				m.logger.Error("Can not collect metric", zap.Error(err))
				continue
			}
			alerts := m.CheckAlerts(metric)
			if len(alerts) > 0 {
				for _, alert := range alerts {
					m.logger.Warn(alert)
				}
			}
		}
	}
}

func TestBackgroundTasks(t *testing.T) {
	tests := []struct {
		name        string
		duration    time.Duration
		assertCalls int
		cancelTask  bool
	}{
		{
			name:        "cancel monitoring cycle",
			duration:    1 * time.Second,
			assertCalls: 0,
			cancelTask:  true,
		},
		{
			name:        "multiple monitoring cycles",
			duration:    1 * time.Second,
			assertCalls: 1000 / tickerOffset,
			cancelTask:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := NewMockResourceMonitor(t)
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			wg.Add(1)
			go func() {
				defer wg.Done()
				mock.StartPeriodicMonitoring(ctx)
			}()

			if tt.cancelTask {
				cancel()
			} else {
				time.Sleep(tt.duration)
				cancel()
			}

			wg.Wait()

			mock.mu.Lock()
			defer mock.mu.Unlock()
			if tt.assertCalls != mock.collectCalled {
				t.Error("cancel did not work")
			}
		})
	}
}
