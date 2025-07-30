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

// generateSelfSignedCert 生成自签名SSL证书
func generateSelfSignedCert() error {
	// 创建证书目录
	certDir := "certs"
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录失败: %v", err)
	}

	// 生成私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"FileServer"},
			Country:       []string{"CN"},
			Province:      []string{"Beijing"},
			Locality:      []string{"Beijing"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
			CommonName:    "FileServer Local Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:              []string{"localhost", "fileserver.local"},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("创建证书失败: %v", err)
	}

	// 保存证书文件
	certPath := filepath.Join(certDir, "server.crt")
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("编码证书失败: %v", err)
	}

	// 保存私钥文件
	keyPath := filepath.Join(certDir, "server.key")
	keyOut, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("创建私钥文件失败: %v", err)
	}
	defer keyOut.Close()

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("序列化私钥失败: %v", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes}); err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}

	// 生成证书信息文件
	infoPath := filepath.Join(certDir, "cert_info.json")

	infoOut, err := os.Create(infoPath)
	if err != nil {
		return fmt.Errorf("创建证书信息文件失败: %v", err)
	}
	defer infoOut.Close()

	// 写入JSON格式的证书信息
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
  "files": {
    "certificate": "server.crt",
    "private_key": "server.key"
  }
}`

	if _, err := infoOut.WriteString(infoJSON); err != nil {
		return fmt.Errorf("写入证书信息失败: %v", err)
	}

	fmt.Printf("✅ SSL证书生成成功！\n")
	fmt.Printf("   证书文件: %s\n", certPath)
	fmt.Printf("   私钥文件: %s\n", keyPath)
	fmt.Printf("   证书信息: %s\n", infoPath)
	fmt.Printf("   有效期: %s 至 %s\n", template.NotBefore.Format("2006-01-02"), template.NotAfter.Format("2006-01-02"))

	return nil
}

func main() {
	fmt.Println("🔐 生成FileServer SSL证书...")

	if err := generateSelfSignedCert(); err != nil {
		log.Fatalf("生成证书失败: %v", err)
	}

	fmt.Println("\n📝 使用说明:")
	fmt.Println("1. 生成的证书是自签名证书，仅用于开发和测试")
	fmt.Println("2. 浏览器会显示安全警告，这是正常的")
	fmt.Println("3. 生产环境请使用CA签发的正式证书")
	fmt.Println("4. 可以通过 /api/v1/certificates API 下载证书")
}