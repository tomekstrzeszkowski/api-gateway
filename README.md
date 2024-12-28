# API Gateway
This project is for learning purposes. 
Key features:
 - Dynamic services registration ✔
 - SSL support ✔
 - Monitoring ✔
 - E2E encription - TODO

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

More Examples:
```
curl localhost:8080/rsa-public
```
```
curl localhost:8080/echo -H "X-Encrypted-Request: fail"
```
## Metrics
```
curl localhost:8080/metrics
```
```
curl localhost:8080/metrics-history
```