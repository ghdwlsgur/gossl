package cmd

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

// convertMode 는 변환 여부를 어떻게 정할지 나타낸다.
// 파일을 인자로 받으면 프롬프트를 띄울 수 없으므로 모드로 대신한다.
type convertMode int

const (
	convertAsk    convertMode = iota // 물어본다 (대화형 기본값)
	convertAlways                    // 묻지 않고 변환한다 (--convert)
	convertNever                     // 변환하지 않고 정보만 보여준다
)

// shouldConvert 는 모드에 따라 변환할지 정한다.
// convertAsk 일 때만 사용자에게 묻는다.
func shouldConvert(mode convertMode, question string, options []string) (bool, error) {
	switch mode {
	case convertAlways:
		return true, nil
	case convertNever:
		return false, nil
	}
	answer, err := internal.AskSelect(question, options)
	if err != nil {
		return false, err
	}
	return strings.Split(answer, " ")[0] == "Yes", nil
}

var (
	_parseCrt = func(fileName string, pem *internal.Pem, mode convertMode) error {
		if len(pem.Data) <= 0 {
			return panicRed(fmt.Errorf("file content is empty"))
		}

		question := fmt.Sprintf("%s %s %s, %s %s %s?",
			color.HiWhiteString("This is"),
			color.HiRedString("CRT"),
			color.HiRedString("(DER incoding)"),
			color.HiWhiteString("Do you want to change to"),
			color.HiGreenString("CERTIFICATE"),
			color.HiGreenString("(PEM incoding)"))
		convert, err := shouldConvert(mode, question,
			[]string{"Yes (create file - PEM incoding)", "No (exit)"})
		if err != nil {
			return err
		}

		if !convert {
			// 변환하지 않으면 무엇인지만 알려준다. 오류가 아니다.
			internal.PrintFunc("Type", color.HiRedString(pem.Type))
			if mode == convertNever {
				fmt.Println(color.HiBlackString("\t\tuse --convert to write a PEM copy"))
			}
			return nil
		}

		if err := internal.CrtToCertificate(fileName, pem.Data); err != nil {
			return panicRed(err)
		}
		fmt.Print(color.HiGreenString("✅ Converted successfully (crt -> pem)"))
		return nil
	}

	_parsePrivateKey = func(fileName string, pem *internal.Pem, mode convertMode) error {
		if len(pem.Data) <= 0 {
			return panicRed(fmt.Errorf("file content is empty"))
		}

		question := fmt.Sprintf("This is %s, Do you want to change to %s ?", color.HiRedString("PRIVATE KEY"), color.HiGreenString("RSA PRIVATE KEY"))
		convert, err := shouldConvert(mode, question,
			[]string{"Yes (Overwrite file)", "No (exit)"})
		if err != nil {
			return err
		}

		if !convert {
			// 변환하지 않으면 무엇인지만 알려준다. 오류가 아니다.
			internal.PrintFunc("Type", color.HiRedString(pem.Type))
			if mode == convertNever {
				fmt.Println(color.HiBlackString("\t\tuse --convert to overwrite as RSA PRIVATE KEY"))
			}
			return nil
		}

		if err := internal.PrivateToRsaPrivate(fileName, pem.Block); err != nil {
			return err
		}
		fmt.Print(color.HiGreenString("✅ Converted successfully (PRIVATE KEY -> RSA PRIVATE KEY)"))
		return nil
	}

	_parseRsaPrivateKey = func(pem *internal.Pem) error {
		if len(pem.Data) <= 0 {
			return panicRed(fmt.Errorf("file content is empty"))
		}
		fmt.Println()
		internal.PrintFunc("Type", color.HiRedString(pem.Type))
		md5, err := internal.GetMd5FromRsaPrivateKey(pem)
		if err != nil {
			return err
		}
		internal.PrintFunc("Md5 Hash", color.HiBlackString(md5.RsaPrivateKey))

		return nil
	}

	_parseCertificate = func(certFile *internal.CertFile, pemBlockCount int, pem *internal.Pem) error {
		if len(pem.Data) <= 0 {
			return panicRed(fmt.Errorf("file content is empty"))
		}

		cert, err := x509.ParseCertificate(pem.Block.Bytes)
		if err != nil {
			return panicRed(err)
		}

		fmt.Printf(color.HiWhiteString("\n%s\n"), strings.Split(cert.Issuer.String(), ",")[0])

		internal.PrintFunc("Verify Host", internal.HostNames(cert))
		internal.PrintSplitFunc("Subject", cert.Subject.String())

		if len(cert.DNSNames) > 0 {
			dnsToString := strings.Join(cert.DNSNames, " ")
			fmt.Printf("%s\t%s\n",
				color.HiBlackString("SAN DNS  "),
				color.HiMagentaString(strings.ReplaceAll(dnsToString, " ", "\n\t\t")))
		}
		internal.PrintSplitFunc("Issuer Name", cert.Issuer.String())
		internal.PrintFunc("Expire Date", cert.NotAfter.Format("2006-January-02"))
		internal.PrintFunc("Type", pem.Type)

		detail, err := internal.DistinguishCertificate(pem, certFile, pemBlockCount)
		if err != nil {
			return err
		}
		internal.PrintFunc("Detail", color.HiMagentaString(detail))

		md5, err := internal.GetMd5FromCertificate(pem)
		if err != nil {
			return err
		}
		internal.PrintFunc("Md5 Hash", color.HiBlackString(md5.Certificate))

		return nil
	}
)

var (
	inspectConvert bool

	// Query certificate or key file type and Md5 hash
	inspectCommand = &cobra.Command{
		Use:     "inspect [file]",
		Aliases: []string{"echo"},
		Short:   "Show the contents of the certificate file/type and compare hashes.",
		Long: `Show the contents of the certificate file/type and compare hashes.

Pass a file to skip the prompt, which is what you want in a pipeline:
  gossl inspect server.crt
  gossl inspect server.key

Without a file it lists the certificates in the current directory and asks.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var file string
			if len(args) == 1 {
				file = args[0]
			}
			return runInspect(file, inspectConvert)
		},
	}
)

// inspectConvertMode 는 파일 인자와 --convert 로 변환 모드를 정한다.
// 파일을 인자로 받았다면 프롬프트를 띄울 수 없으므로 묻지 않는다.
func inspectConvertMode(file string, convert bool) convertMode {
	switch {
	case convert:
		return convertAlways
	case file != "":
		return convertNever
	default:
		return convertAsk
	}
}

// runInspect 는 인증서·키 파일 하나의 내용을 보여준다.
// file 이 비어 있으면 현재 디렉토리에서 고르게 한다.
func runInspect(file string, convert bool) error {
	certFile, fileName, err := resolveCertFile("Select Certificate File", file)
	if err != nil {
		return panicRed(err)
	}

	data, err := os.ReadFile(fileName)
	if err != nil {
		return panicRed(err)
	}
	pemBlockCount := internal.CountPemBlock(bytes.TrimSpace(data))

	internal.SetCertExtension(certFile, fileName)

	p, err := internal.GetPemType(fileName)
	if err != nil {
		return panicRed(err)
	}

	mode := inspectConvertMode(file, convert)

	switch p.Type {
	case "PRIVATE KEY":
		err = _parsePrivateKey(fileName, p, mode)
	case "RSA PRIVATE KEY":
		err = _parseRsaPrivateKey(p)
	case "CERTIFICATE":
		err = _parseCertificate(certFile, pemBlockCount, p)
	case "CRT":
		err = _parseCrt(fileName, p, mode)
	default:
		return panicRed(fmt.Errorf("sorry, %s isn't supported", p.Type))
	}
	if err != nil {
		return err
	}

	fmt.Println()
	return nil
}

func init() {
	inspectCommand.Flags().BoolVar(&inspectConvert, "convert", false,
		"[optional] convert CRT to PEM or PRIVATE KEY to RSA PRIVATE KEY without asking")

	rootCmd.AddCommand(inspectCommand)
}
