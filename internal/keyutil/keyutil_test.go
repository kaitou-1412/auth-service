package keyutil_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/kaitou-1412/auth-service/internal/keyutil"
)

func generateTestKeys(t *testing.T, dir string) (privPath, pubPath string) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	// Write private key (PKCS8)
	privBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	privPath = filepath.Join(dir, "private.pem")
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		t.Fatalf("failed to write private key: %v", err)
	}

	// Write public key (PKIX)
	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPath = filepath.Join(dir, "public.pem")
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	if err := os.WriteFile(pubPath, pubPEM, 0600); err != nil {
		t.Fatalf("failed to write public key: %v", err)
	}

	return privPath, pubPath
}

func TestLoadPrivateKey_Valid(t *testing.T) {
	dir := t.TempDir()
	privPath, _ := generateTestKeys(t, dir)

	key, err := keyutil.LoadPrivateKey(privPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestLoadPublicKey_Valid(t *testing.T) {
	dir := t.TempDir()
	_, pubPath := generateTestKeys(t, dir)

	key, err := keyutil.LoadPublicKey(pubPath)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestLoadPrivateKey_FileNotFound(t *testing.T) {
	_, err := keyutil.LoadPrivateKey("/nonexistent/path/private.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPublicKey_FileNotFound(t *testing.T) {
	_, err := keyutil.LoadPublicKey("/nonexistent/path/public.pem")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadPrivateKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := keyutil.LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadPublicKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatal(err)
	}

	_, err := keyutil.LoadPublicKey(path)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestLoadPrivateKey_InvalidKeyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")})
	if err := os.WriteFile(path, badPEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := keyutil.LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error for invalid key data")
	}
}

func TestLoadPublicKey_InvalidKeyData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.pem")
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")})
	if err := os.WriteFile(path, badPEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err := keyutil.LoadPublicKey(path)
	if err == nil {
		t.Fatal("expected error for invalid key data")
	}
}

func TestLoadPrivateKey_NotRSA(t *testing.T) {
	dir := t.TempDir()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecBytes, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "ec.pem")
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecBytes})
	if err := os.WriteFile(path, ecPEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err = keyutil.LoadPrivateKey(path)
	if err == nil {
		t.Fatal("expected error for non-RSA key")
	}
}

func TestLoadPublicKey_NotRSA(t *testing.T) {
	dir := t.TempDir()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPubBytes, err := x509.MarshalPKIXPublicKey(&ecKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "ec_pub.pem")
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: ecPubBytes})
	if err := os.WriteFile(path, ecPEM, 0600); err != nil {
		t.Fatal(err)
	}

	_, err = keyutil.LoadPublicKey(path)
	if err == nil {
		t.Fatal("expected error for non-RSA public key")
	}
}
