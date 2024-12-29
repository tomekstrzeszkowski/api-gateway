FROM golang:1.23 AS builder
WORKDIR /app/

#dlv
RUN go install github.com/go-delve/delve/cmd/dlv@latest

COPY . .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -gcflags="-N -l" -a -o main .


FROM debian:bookworm-slim
WORKDIR /app/
COPY --from=builder /app/main main
COPY --from=builder /go/bin/dlv /
COPY /external/cert.pem /secr/cert.pem
COPY /external/private.key /secr/private.key
EXPOSE 8080 2345

CMD ["./main"]