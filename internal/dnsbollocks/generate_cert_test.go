package dnsbollocks

import (
	"crypto/x509"
	"log/slog"
	"net"
	"os"
	"testing"
)

func TestGenerateCertIfNeeded(t *testing.T) {
	// Setup a temporary directory so we don't overwrite real certs
	tempDir := t.TempDir()
	originalWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	
	// Change working directory to temp dir so "cert.pem" is written safely
	err = os.Chdir(tempDir)
	if err != nil {
		t.Fatalf("failed to change working directory: %v", err)
	}
	defer os.Chdir(originalWD) // Ensure we go back after the test

	// Helper to create a basic server instance
	newTestServer := func(dohAddr, uiAddr string) *Server {
		s := &Server{}
		cfg := &Config{
			ListenDoH: dohAddr,
			ListenUI:  uiAddr,
		}
		s.liveConfig.Store(cfg)
		
		// Use a silent logger for tests to reduce console noise
		nopLogger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
		s.liveLogger.Store(nopLogger)
		
		return s
	}

	t.Run("Generates New Cert When None Exists", func(t *testing.T) {
		s := newTestServer("127.0.0.1:443", "192.168.1.50:8080")
		
		// Run generation
		s.generateCertIfNeeded()

		// Verify generation counter incremented
		if s.certGeneration.Load() != 1 {
			t.Errorf("Expected certGeneration counter to be 1, got %d", s.certGeneration.Load())
		}

		// Verify cert was loaded into memory
		if len(s.dohCert.Certificate) == 0 {
			t.Fatal("Expected s.dohCert to be loaded, but it is empty")
		}

		// Verify both IPs are in the certificate
		leaf, err := x509.ParseCertificate(s.dohCert.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to parse loaded certificate: %v", err)
		}

		expectedIPs := []string{"127.0.0.1", "192.168.1.50"}
		for _, expectedStr := range expectedIPs {
			expectedIP := net.ParseIP(expectedStr)
			found := false
			for _, ip := range leaf.IPAddresses {
				if ip.Equal(expectedIP) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected IP %s in certificate, but it was missing", expectedStr)
			}
		}
	})

	t.Run("Skips Generation When Valid Cert Exists", func(t *testing.T) {
		// Relying on the cert generated in the previous subtest
		s := newTestServer("127.0.0.1:443", "192.168.1.50:8080")
		
		// Run generation
		s.generateCertIfNeeded()

		// Verify generation counter did NOT increment (should be 0 for this new server instance)
		if s.certGeneration.Load() != 0 {
			t.Errorf("Expected certGeneration counter to be 0 (skipped), got %d", s.certGeneration.Load())
		}
	})

	t.Run("Regenerates When UI IP Changes", func(t *testing.T) {
		// Keep DoH the same, but change the UI address
		s := newTestServer("127.0.0.1:443", "10.0.0.5:8080")
		
		// Run generation
		s.generateCertIfNeeded()

		// Verify it detected the mismatch and regenerated
		if s.certGeneration.Load() != 1 {
			t.Errorf("Expected certGeneration counter to be 1 (regenerated), got %d", s.certGeneration.Load())
		}

		// Verify new IP is in the certificate
		leaf, err := x509.ParseCertificate(s.dohCert.Certificate[0])
		if err != nil {
			t.Fatalf("Failed to parse loaded certificate: %v", err)
		}

		newExpectedIP := net.ParseIP("10.0.0.5")
		found := false
		for _, ip := range leaf.IPAddresses {
			if ip.Equal(newExpectedIP) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected new UI IP 10.0.0.5 in regenerated certificate, but it was missing")
		}
	})
	
	t.Run("Handles DNS Names (Localhost)", func(t *testing.T) {
		s := newTestServer("localhost:443", "localhost:8080")
		
		// Clear out old files so it's forced to generate fresh
		os.Remove("cert.pem")
		os.Remove("key.pem")
		
		s.generateCertIfNeeded()
		
		if s.certGeneration.Load() != 1 {
			t.Errorf("Expected generation counter to be 1, got %d", s.certGeneration.Load())
		}
		
		leaf, _ := x509.ParseCertificate(s.dohCert.Certificate[0])
		
		found := false
		for _, name := range leaf.DNSNames {
			if name == "localhost" {
				found = true
				break
			}
		}
		
		if !found {
			t.Errorf("Expected DNSName 'localhost' in certificate, but it was missing")
		}
	})
}