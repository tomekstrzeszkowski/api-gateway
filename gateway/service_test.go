package gateway

import (
	"testing"
)

func TestStruct(t *testing.T) {
	val := &ServiceConfig{
		Name:    "user",
		BaseUrl: "localhost:8080",
	}
	if val.Name != "user" {
		t.Errorf("got %q, wanted %q", val.Name, "user")
	}
}
