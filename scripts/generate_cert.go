package main

import (
    "crypto/rand"
    "crypto/rsa"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "fmt"
    "log"
    "math/big"
    "net"
    "os"
    "path/filepath"
    "time"
)

// generateSelfSignedCert generates a self-signed SSL certificate (for dev/testing)
func generateSelfSignedCert() error {
    // Ensure cert directory exists
    certDir := "certs"
    if err := os.MkdirAll(certDir, 0755); err != nil {
        return fmt.Errorf("failed to create cert directory: %v", err)
    }

    // Generate private key
    privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
    if err != nil {
        return fmt.Errorf("failed to generate private key: %v", err)
    }

    // Create certificate template
    template := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject: pkix.Name{
            Organization:  []string{"FileServer"},
            Country:       []string{"CN"},
            Province:      []string{"Beijing"},
            Locality:      []string{"Beijing"},
            CommonName:    "FileServer Local Certificate",
        },
        NotBefore:             time.Now(),
        NotAfter:              time.Now().Add(365 * 24 * time.Hour),
        KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid: true,
        IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
        DNSNames:              []string{"localhost", "fileserver.local"},
    }

    // Create certificate
    certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
    if err != nil {
        return fmt.Errorf("failed to create certificate: %v", err)
    }

    // Save certificate file
    certPath := filepath.Join(certDir, "server.crt")
    certOut, err := os.Create(certPath)
    if err != nil {
        return fmt.Errorf("failed to create certificate file: %v", err)
    }
    defer certOut.Close()
    if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
        return fmt.Errorf("failed to encode certificate: %v", err)
    }

    // Save private key file
    keyPath := filepath.Join(certDir, "server.key")
    keyOut, err := os.Create(keyPath)
    if err != nil {
        return fmt.Errorf("failed to create private key file: %v", err)
    }
    defer keyOut.Close()
    privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
    if err != nil {
        return fmt.Errorf("failed to serialize private key: %v", err)
    }
    if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
        return fmt.Errorf("failed to encode private key: %v", err)
    }

    // Save certificate metadata (JSON)
    infoPath := filepath.Join(certDir, "cert_info.json")
    infoOut, err := os.Create(infoPath)
    if err != nil {
        return fmt.Errorf("failed to create cert info file: %v", err)
    }
    defer infoOut.Close()

    infoJSON := `{
  "subject": {
    "common_name": "` + template.Subject.CommonName + `",
    "organization": ["` + template.Subject.Organization[0] + `"],
    "country": ["` + template.Subject.Country[0] + `"],
    "province": ["` + template.Subject.Province[0] + `"],
    "locality": ["` + template.Subject.Locality[0] + `"]
  },
  "validity": {
    "not_before": "` + template.NotBefore.Format(time.RFC3339) + `",
    "not_after": "` + template.NotAfter.Format(time.RFC3339) + `"
  },
  "key_usage": ["Digital Signature", "Key Encipherment"],
  "ext_key_usage": ["Server Authentication"],
  "dns_names": ["localhost", "fileserver.local"],
  "ip_addresses": ["127.0.0.1", "::1"],
  "serial_number": "` + template.SerialNumber.String() + `",
  "key_size": 2048,
  "signature_algorithm": "SHA256-RSA",
  "files": {"certificate": "server.crt", "private_key": "server.key"}
}`
    if _, err := infoOut.WriteString(infoJSON); err != nil {
        return fmt.Errorf("failed to write cert info: %v", err)
    }

    fmt.Printf("✅ SSL certificate generated successfully!\n")
    fmt.Printf("   Certificate: %s\n", certPath)
    fmt.Printf("   Private Key: %s\n", keyPath)
    fmt.Printf("   Info File:   %s\n", infoPath)
    fmt.Printf("   Validity:    %s to %s\n", template.NotBefore.Format("2006-01-02"), template.NotAfter.Format("2006-01-02"))
    return nil
}

func main() {
    fmt.Println("🔐 Generating FileServer SSL certificate...")
    if err := generateSelfSignedCert(); err != nil {
        log.Fatalf("failed to generate certificate: %v", err)
    }
    fmt.Println("\n📝 Notes:")
    fmt.Println("1. This is a self-signed certificate for development and testing only.")
    fmt.Println("2. Browsers may show security warnings — this is expected.")
    fmt.Println("3. Use a CA-signed certificate for production deployments.")
    fmt.Println("4. The certificate can be downloaded via /api/v1/certificates API.")
}

