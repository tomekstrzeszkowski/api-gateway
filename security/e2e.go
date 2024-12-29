package security

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httputil"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type responseWriter struct {
	gin.ResponseWriter
	body *bytes.Buffer
	sm   *SecurityManager
}

func wrapResponseWriter(c *gin.Context, sm *SecurityManager) *responseWriter {
	return &responseWriter{
		ResponseWriter: c.Writer,
		body:           new(bytes.Buffer),
		sm:             sm,
	}
}

func (w *responseWriter) Write(b []byte) (int, error) {
	return w.body.Write(b)
}

func (w *responseWriter) WriteHeader(code int) {
	w.ResponseWriter.WriteHeader(code)
}
func (w *responseWriter) Flush() {
	bodyBytes := w.body.Bytes()
	if len(bodyBytes) > 0 {
		// Decrypt the response body
		decrypted, err := w.sm.DecryptRSA(string(bodyBytes))
		if err != nil {
			w.ResponseWriter.WriteHeader(http.StatusInternalServerError)
			w.ResponseWriter.Write([]byte(`{"error": "Failed to decrypt response"}`))
			return
		}
		w.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(decrypted)))
		w.ResponseWriter.Write([]byte(decrypted))
	}
}

func E2eEncryptionHandler(c *gin.Context, sm *SecurityManager, serviceProxy *httputil.ReverseProxy) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), 10*time.Second)
	defer cancel()
	c.Request = c.Request.WithContext(ctx)

	//send encrypted data
	contentLength := c.Request.ContentLength
	if contentLength < 1 {
		return
	}
	bodyBytes := make([]byte, contentLength)
	_, err := io.ReadFull(c.Request.Body, bodyBytes)
	if err != nil {
		c.Request.Header.Set("Content-Length", "0")
		c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte{}))
		return
	}
	encryptedBody, err := sm.EncryptRSA(bodyBytes)
	if err != nil {
		c.Request.Header.Set("Content-Length", "0")
		c.Request.Body = io.NopCloser(bytes.NewBuffer([]byte{}))
		return
	}
	encryptedBytes := []byte(encryptedBody)
	c.Request.ContentLength = int64(len(encryptedBytes))
	c.Request.Header.Set("Content-Length", strconv.Itoa(len(encryptedBytes)))
	c.Request.Body = io.NopCloser(bytes.NewBuffer(encryptedBytes))

	//decrypt received encrypted data
	wrappedWriter := wrapResponseWriter(c, sm)
	c.Writer = wrappedWriter

	serviceProxy.ServeHTTP(c.Writer, c.Request)
	wrappedWriter.Flush()
}
