package monitoring

import "testing"

func TestBackgroundTask(t *testing.T) {
	rm, err := NewResourceMonitor()
	if err != nil {
		t.Error("encrypted should be a string")
	}
}
