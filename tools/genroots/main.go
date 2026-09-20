// Command genroots 는 CCADB 에서 루트 인증서 목록을 받아
// config/roots.pem 번들을 만든다.
//
// CCADB(Common CA Database)는 Mozilla 가 운영하고 Google, Apple, Microsoft 가
// 함께 쓰는 루트 인증서 데이터베이스다. CSV 에 인증서 본문(PEM Info)이 들어
// 있어 벤더별 다운로드 URL 이 필요 없다.
//
// 걸러내는 것
//   - Trust Bits 에 Websites 가 없는 것 (S/MIME 전용)
//   - Distrust for TLS After Date 가 지난 것
//   - 이미 만료된 것
//
// 사용:
//
//	go run ./tools/genroots
package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

const ccadbURL = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReportPEMCSV"

type root struct {
	name        string
	owner       string
	fingerprint string
	notAfter    time.Time
	der         []byte
}

func main() {
	if code := runMain(os.Args[1:], os.Stdout, os.Stderr); code != 0 {
		os.Exit(code)
	}
}

// runMain 은 인자를 해석하고 종료 코드를 돌려준다.
// 프로세스를 끝내지 않으므로 테스트가 직접 부를 수 있다.
func runMain(args []string, out, errOut io.Writer) int {
	fs := flag.NewFlagSet("genroots", flag.ContinueOnError)
	fs.SetOutput(errOut)
	dst := fs.String("o", "config/roots.pem", "생성할 번들 경로")
	src := fs.String("url", ccadbURL, "CCADB CSV 주소")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if err := run(*src, *dst, out); err != nil {
		fmt.Fprintln(errOut, "genroots:", err)
		return 1
	}
	return 0
}

func run(src, dst string, out io.Writer) error {
	records, err := fetch(src)
	if err != nil {
		return err
	}

	roots, skipped, err := parse(records, time.Now())
	if err != nil {
		return err
	}
	if len(roots) == 0 {
		return fmt.Errorf("남은 루트 인증서가 없다, CSV 형식이 바뀌었을 수 있다")
	}

	sort.Slice(roots, func(i, j int) bool { return roots[i].name < roots[j].name })

	if err := write(dst, roots); err != nil {
		return err
	}

	fmt.Fprintf(out, "%s 생성: 루트 %d개 (제외 %d개)\n", dst, len(roots), skipped)
	return nil
}

func fetch(src string) ([]map[string]string, error) {
	resp, err := http.Get(src)
	if err != nil {
		return nil, fmt.Errorf("CCADB 요청 실패: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("CCADB 응답 %s", resp.Status)
	}

	r := csv.NewReader(resp.Body)
	r.FieldsPerRecord = -1
	rows, err := r.ReadAll()
	if err != nil {
		return nil, fmt.Errorf("CSV 파싱 실패: %w", err)
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("CSV 에 데이터가 없다")
	}

	header := rows[0]
	records := make([]map[string]string, 0, len(rows)-1)
	for _, row := range rows[1:] {
		m := make(map[string]string, len(header))
		for i, h := range header {
			if i < len(row) {
				m[h] = row[i]
			}
		}
		records = append(records, m)
	}
	return records, nil
}

func parse(records []map[string]string, now time.Time) ([]root, int, error) {
	var roots []root
	skipped := 0
	seen := map[string]bool{}

	for _, rec := range records {
		// TLS 용이 아닌 루트는 이 도구의 대상이 아니다.
		if !strings.Contains(rec["Trust Bits"], "Websites") {
			skipped++
			continue
		}

		// TLS 신뢰가 철회된 루트는 싣지 않는다.
		if d := strings.TrimSpace(rec["Distrust for TLS After Date"]); d != "" {
			if t, err := time.Parse("2006.01.02", d); err == nil && now.After(t) {
				skipped++
				continue
			}
		}

		block, _ := pem.Decode([]byte(strings.Trim(strings.TrimSpace(rec["PEM Info"]), "'")))
		if block == nil {
			skipped++
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			skipped++
			continue
		}
		if now.After(cert.NotAfter) {
			skipped++
			continue
		}

		sum := sha256.Sum256(cert.Raw)
		fp := strings.ToUpper(hex.EncodeToString(sum[:]))

		// CCADB 가 알려준 지문과 대조한다. 어긋나면 데이터가 깨진 것이다.
		if want := strings.ToUpper(strings.TrimSpace(rec["SHA-256 Fingerprint"])); want != "" && want != fp {
			return nil, 0, fmt.Errorf("지문 불일치: %s (CCADB %s, 계산 %s)", rec["Common Name or Certificate Name"], want, fp)
		}
		if seen[fp] {
			continue
		}
		seen[fp] = true

		roots = append(roots, root{
			name:        displayName(cert, rec["Common Name or Certificate Name"]),
			owner:       strings.TrimSpace(rec["Owner"]),
			fingerprint: fp,
			notAfter:    cert.NotAfter,
			der:         cert.Raw,
		})
	}
	return roots, skipped, nil
}

// displayName 은 사용자에게 보여줄 이름을 고른다.
// 인증서의 CN 을 우선하고, 비어 있으면 O, 그것도 없으면 CCADB 이름을 쓴다.
func displayName(cert *x509.Certificate, fallback string) string {
	if cn := strings.TrimSpace(cert.Subject.CommonName); cn != "" {
		return cn
	}
	if len(cert.Subject.Organization) > 0 {
		if o := strings.TrimSpace(cert.Subject.Organization[0]); o != "" {
			return o
		}
	}
	return strings.TrimSpace(fallback)
}

func write(path string, roots []root) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	header := fmt.Sprintf(`## gossl root certificate bundle
##
## 이 파일은 tools/genroots 가 CCADB 에서 생성한다. 직접 고치지 마라.
##   go run ./tools/genroots
##
## Source: %s
## Roots:  %d
##
## TLS 신뢰(Websites) 가 있고, 신뢰가 철회되지 않았으며, 만료되지 않은
## 루트만 담는다. 각 인증서 위의 주석은 참고용이고 이름과 지문은 인증서
## 자체에서 다시 계산되므로 어긋날 수 없다.

`, ccadbURL, len(roots))

	if _, err := io.WriteString(f, header); err != nil {
		return err
	}

	for _, r := range roots {
		block := &pem.Block{Type: "CERTIFICATE", Bytes: r.der}
		meta := fmt.Sprintf("# %s\n# Owner: %s\n# SHA-256: %s\n# Not After: %s\n",
			r.name, r.owner, r.fingerprint, r.notAfter.UTC().Format("2006-01-02"))
		if _, err := io.WriteString(f, meta); err != nil {
			return err
		}
		if err := pem.Encode(f, block); err != nil {
			return err
		}
		if _, err := io.WriteString(f, "\n"); err != nil {
			return err
		}
	}
	return f.Close()
}
