package gateway

import (
	"example.com/m/v2/security"
)

type ServiceConfig struct {
	Name                          string
	BaseUrl                       string
	Certificate                   *string
	PrivateKey                    *string
	Scheme                        string
	CertificateInsecureSkipVerify *bool
	SecurityManager               *security.SecurityManager
}
