# Generate private key
```
openssl genrsa -out private.key 2048
```

# Generate a self-signed certificate using the private key
```
openssl req -new -x509 -key private.key -out cert.pem -days 365 -config cert.conf
```

# Generate public key
```
openssl rsa -in private.key -pubout -out public.pem
```

# Example
```
curl --cacert ./external/cert.pem -X POST -d "param1=value1&param2=value2" https://127.0.0.1:8002
```