package internal

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/ghdwlsgur/gossl/config"
)

// RootCertificate 는 내장 번들에 들어 있는 루트 인증서 하나다.
type RootCertificate struct {
	Name        string
	Fingerprint string // SHA-256, 대문자 hex
	Certificate *x509.Certificate
	PEM         []byte
}

var (
	rootsOnce sync.Once
	rootsList []RootCertificate
	rootsErr  error
)

// RootCertificates 는 내장된 루트 인증서를 이름순으로 돌려준다.
//
// 번들은 주석과 PEM 블록이 섞인 평범한 PEM 파일이다. 이름과 지문은 주석이
// 아니라 인증서 자체에서 다시 계산하므로 주석과 어긋날 수 없다.
func RootCertificates() ([]RootCertificate, error) {
	rootsOnce.Do(func() {
		rootsList, rootsErr = parseRootBundle(config.Roots)
	})
	return rootsList, rootsErr
}

func parseRootBundle(data []byte) ([]RootCertificate, error) {
	var out []RootCertificate

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse embedded root certificate: %w", err)
		}

		sum := sha256.Sum256(cert.Raw)
		out = append(out, RootCertificate{
			Name:        rootDisplayName(cert),
			Fingerprint: strings.ToUpper(hex.EncodeToString(sum[:])),
			Certificate: cert,
			PEM:         pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}),
		})
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("embedded root certificate bundle is empty")
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func rootDisplayName(cert *x509.Certificate) string {
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if len(cert.Subject.Organization) > 0 {
		if o := strings.TrimSpace(cert.Subject.Organization[0]); o != "" {
			return o
		}
	}
	return cert.Subject.String()
}

// RootCertificateNames 는 고르기 위한 이름 목록이다.
func RootCertificateNames() ([]string, error) {
	roots, err := RootCertificates()
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(roots))
	for _, r := range roots {
		names = append(names, r.Name)
	}
	return names, nil
}

// FindRootCertificate 는 이름으로 루트 인증서를 찾는다.
func FindRootCertificate(name string) (RootCertificate, error) {
	roots, err := RootCertificates()
	if err != nil {
		return RootCertificate{}, err
	}
	for _, r := range roots {
		if r.Name == name {
			return r, nil
		}
	}
	return RootCertificate{}, fmt.Errorf("root certificate not found: %s", name)
}

// SaveRootCertificate 는 루트 인증서를 현재 디렉토리에 PEM 으로 저장한다.
// out 은 사용자 입력이므로 파일명만 취해 상위 경로로 빠져나가지 못하게 한다.
func SaveRootCertificate(root RootCertificate, out string) (string, error) {
	name := filepath.Base(filepath.Clean(out))
	if name == "." || name == string(filepath.Separator) {
		return "", fmt.Errorf("invalid output file name: %q", out)
	}

	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, root.PEM, 0o644); err != nil {
		return "", err
	}
	return path, nil
}
