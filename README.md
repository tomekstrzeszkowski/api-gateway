# API Gateway
This project is for learning purposes.

Key features:
 - Dynamic services registration ✔
 - Secure Socket Layer (SSL) support ✔
 - Monitoring ✔
 - Customized E2E encryptions (for those who take security *very* seriously) ✔

# Debugging

Create `docker.compose.override.yml`, 
see template: `docker.compose.override.debugging.yml`,
```
docker compose up --bulid
```
Run IDE debugger.

# Usage

## Register all services

```
curl -X POST localhost:8080/register-services/all
```

Test registered services
```
curl -X GET localhost:8080/echo
```

## More examples

Test SSL certificate
```
curl -X POST localhost:8080/cert -d "param1=value1&param2=value2"
```

Export public key for testing
```
curl localhost:8080/rsa-public
```

Customized X-Header message, to encrypt message use public key,
see: `security_test.go` or `secure_server.py` for more details.
```
curl localhost:8080/echo -H "X-Encrypted-Request: fail"
```

Customized E2E encryption, the gateway encrypts the request body before sending
the data. The external server decodes that data, add some extra text and encode
it again. The gateway reads the response and decode it, therefore, you should 
see the additional data added by external server. Gateway use its own private key
for decrypting data, and public pem imported from external server for encrypting
data. Same thing is done for the external server, thanks to this private keys
are never shared, only public.pem are exchanged.
```
curl -X POST localhost:8080/e2e -d "param1=value1&param2=value2"
```
## Metrics
```
curl localhost:8080/metrics
```
```
curl localhost:8080/metrics-history
```