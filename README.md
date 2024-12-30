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

Customized E2E encryption ensures that the gateway encrypts the request body 
before sending the data. The external server decodes the data, adds some extra
text, and encodes it again. The gateway reads the response and decodes it. 
Therefore, you should see the additional data added by the external server. 
The gateway uses its own private key for decrypting data and the public PEM 
imported from the external server for encrypting data. The same process is 
applied on the external server. Thanks to this approach, private keys are 
never shared, only public PEM files are exchanged.
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