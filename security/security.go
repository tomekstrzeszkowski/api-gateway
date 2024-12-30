package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

type SecurityManager struct {
	privateKey            *rsa.PrivateKey
	publicKey             *rsa.PublicKey
	aesKey                []byte
	mu                    sync.RWMutex
	Certificate           *string
	skipCertificateVerify *bool
}

func ReadPrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8 format if PKCS1 fails
		pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}

		var ok bool
		privateKey, ok = pkcs8Key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
	}

	return privateKey, nil
}

func ReadPublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %w", err)
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// Try PKIX format if PKCS1 fails
		pkixKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}

		var ok bool
		publicKey, ok = pkixKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA public key")
		}
	}

	return publicKey, nil
}

func NewSecurityManager(
	key, certificate *string, certificateSkipVerify *bool, publicKeyPath *string,
) (*SecurityManager, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if key == nil {
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		privateKey, err = ReadPrivateKeyFromFile(*key)
	}
	if err != nil {
		return nil, err
	}

	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, aesKey); err != nil {
		return nil, err
	}
	var publicKey *rsa.PublicKey
	if publicKeyPath == nil {
		publicKey = &privateKey.PublicKey
	} else {
		publicKey, err = ReadPublicKeyFromFile(*publicKeyPath)
		if err != nil {
			return nil, err
		}
	}
	return &SecurityManager{
		privateKey:            privateKey,
		publicKey:             publicKey,
		aesKey:                aesKey,
		Certificate:           certificate,
		skipCertificateVerify: certificateSkipVerify,
	}, nil
}

// private key encryption
func (sm *SecurityManager) EncryptRSA(data []byte) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, sm.publicKey, data)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes), nil
}

func (sm *SecurityManager) DecryptRSA(encrypted string) ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	encryptedBytes, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	data, err := rsa.DecryptPKCS1v15(rand.Reader, sm.privateKey, encryptedBytes)
	if err != nil {
		return nil, err
	}
	return data, nil

}

// static AES key encryption
func (sm *SecurityManager) EncryptAES(data []byte) (string, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	block, err := aes.NewCipher(sm.aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, data, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

func (sm *SecurityManager) DecryptAES(encrypted string) ([]byte, error) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sealed, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(sm.aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, errors.New("encrypted value too short")
	}
	nonce, cipherText := sealed[:nonceSize], sealed[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}

func (sm *SecurityManager) HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func (sm *SecurityManager) CheckPasswordHash(password, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
func (sm *SecurityManager) ExportPublicKey() ([]byte, error) {
	publicBytes := x509.MarshalPKCS1PublicKey(sm.publicKey)
	publicPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicBytes,
		},
	)
	return publicPEM, nil
}

func (sm *SecurityManager) GetTlsConfig() *tls.Config {
	skipVerify := false
	if sm.skipCertificateVerify != nil {
		skipVerify = *sm.skipCertificateVerify
	}
	caCert, err := os.ReadFile(*sm.Certificate)
	if err != nil {
		log.Fatalf("Failed to read CA cert: %v", err)
	}
	rootCAs := x509.NewCertPool()
	rootCAs.AppendCertsFromPEM(caCert)

	return &tls.Config{
		RootCAs:            rootCAs,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify,
	}
}

func (sm *SecurityManager) MiddlewareEncryption() gin.HandlerFunc {
	return func(c *gin.Context) {
		if encryptedHeader := c.GetHeader("X-Encrypted-Request"); encryptedHeader != "" {
			secretMessage, err := sm.DecryptRSA(encryptedHeader)
			if err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "Decryption error"})
				c.Abort()
				return
			}
			fmt.Print(secretMessage)
		}
		c.Next()
	}
}

func (sm *SecurityManager) EndpointExposePublicKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		publicKey, _ := sm.ExportPublicKey()
		c.JSON(http.StatusOK, gin.H{
			"public": string(publicKey),
		})
	}
}
