package security

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
)

func TestEncryptMessage(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	secret := []byte("super secret")
	encrypted, err := sm.EncryptRSA(secret)
	if err != nil {
		t.Error("encrypted should be a string")
	}
	if encrypted == "super secret" {
		t.Errorf("encryption is '%s'", encrypted)
	}
}

func TestDecryptMessage(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	encrypted, _ := sm.EncryptRSA([]byte("Secret Message"))
	decrypted, _ := sm.DecryptRSA(encrypted)
	if string(decrypted) != "Secret Message" {
		t.Error("can not decrypt message")
	}
}

func TestAESDecrypt(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	encrypted, _ := sm.EncryptAES([]byte("Another secret"))
	decrypted, _ := sm.DecryptAES(encrypted)
	if string(decrypted) != "Another secret" {
		t.Error("can not decrypt message")
	}
}

func TestExportKey(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	publicKeyPEM, err := sm.ExportPublicKey()
	if err != nil {
		t.Error("export key failed")
	}
	if string(publicKeyPEM[:31]) != "-----BEGIN RSA PUBLIC KEY-----\n" {
		t.Error("unrecognized key")
	}
}
func TestExportAndDecrypt(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	publicKeyPEM, _ := sm.ExportPublicKey()
	block, _ := pem.Decode(publicKeyPEM)
	pub, _ := x509.ParsePKCS1PublicKey(block.Bytes)

	client_secret, _ := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte("secret message!"))
	client_message, _ := sm.DecryptRSA(base64.StdEncoding.EncodeToString(client_secret))
	if string(client_message) != "secret message!" {
		t.Error("can not decrypt message using exported key")
	}
}
func TestHashPassword(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	hash, err := sm.HashPassword("password123")
	if err != nil {
		t.Error("hasing password")
	}
	if hash == "password123" {
		t.Error("password not secured")
	}
}

func TestCheckingCorrectPassword(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	hash, _ := sm.HashPassword("123pass")
	if !sm.CheckPasswordHash("123pass", hash) {
		t.Error("password hash did not match")
	}
}
func TestCheckingIncorrectPassword(t *testing.T) {
	sm, _ := NewSecurityManager(nil, nil, nil, nil)
	hash, _ := sm.HashPassword("123pass")
	if sm.CheckPasswordHash("223pass", hash) {
		t.Error("password matched")
	}
}
