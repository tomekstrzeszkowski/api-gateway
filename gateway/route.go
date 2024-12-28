package gateway

type Route struct {
	Path        string
	ServiceName string
	Methods     []string
	Ready       bool
}
