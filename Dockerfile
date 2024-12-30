FROM golang:1.23 AS builder
WORKDIR /app/

#dlv
RUN go install github.com/go-delve/delve/cmd/dlv@latest

COPY . .

# import cert and public key
COPY /external/cert.pem /secr/cert.pem
COPY /external/public.pem /secr/public.pem
COPY /private.key /secr/gateway/private.key
RUN rm -rf /external

RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -gcflags="-N -l" -a -o main .


FROM debian:bookworm-slim
WORKDIR /app/
COPY --from=builder /app/main main
COPY --from=builder /go/bin/dlv /
COPY --from=builder /secr/gateway/private.key /secr/gateway/private.key
COPY --from=builder /secr/cert.pem /secr/cert.pem
COPY --from=builder /secr/public.pem /secr/public.pem

EXPOSE 8080 2345

CMD ["./main"]