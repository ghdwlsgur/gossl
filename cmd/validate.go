package cmd

import (
	"fmt"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

func setDomain(args []string) (string, error) {
	if len(args) < 1 || args[0] == "" {
		return "", fmt.Errorf("please enter your domain. ex) gossl validate naver.com")
	}
	return args[0], nil
}

var (
	validateCommand = &cobra.Command{
		Use:   "validate",
		Short: "Check the certificate information applied to the domain.",
		Long:  "Check the certificate information applied to the domain.",
		RunE: func(_ *cobra.Command, args []string) error {
			return runValidate(args)
		},
	}
)

// resolveIPv4 는 도메인이 실재하는지 확인하고 IPv4 주소 목록을 돌려준다.
// check 와 validate 가 같은 검사를 하므로 한 곳에 모았다.
func resolveIPv4(args []string) (string, []string, error) {
	domain, err := setDomain(args)
	if err != nil {
		return "", nil, err
	}

	if err := internal.GetHost(domain); err != nil {
		return "", nil, err
	}

	ips, err := internal.GetRecordIPv4(domain)
	if err != nil {
		return "", nil, err
	}
	if len(ips) == 0 {
		return "", nil, fmt.Errorf("no IPv4 address found for %s, this domain may be IPv6 only", domain)
	}
	return domain, ips, nil
}

// runValidate 는 A 레코드마다 직접 접속해 엣지별 인증서를 보여준다.
func runValidate(args []string) error {
	domain, ips, err := resolveIPv4(args)
	if err != nil {
		return panicRed(err)
	}

	for _, ip := range ips {
		if err := internal.GetCertificateInfo(ip, domain); err != nil {
			return panicRed(err)
		}
	}
	return nil
}

func init() {
	rootCmd.AddCommand(validateCommand)
}
