package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

// writeUnlockedKey 는 복호화한 키를 원자적으로 교체한다.
// 원본을 먼저 비우면 이후 단계가 실패했을 때 개인키를 잃는다.
func writeUnlockedKey(fileName string, der []byte) error {
	info, err := os.Stat(fileName)
	if err != nil {
		return err
	}

	tmp, err := os.CreateTemp(filepath.Dir(fileName), filepath.Base(fileName)+".*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		tmp.Close()
		return err
	}
	if err := pem.Encode(tmp, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, fileName)
}

var (
	unlockPasswordFile string

	unlockCommand = &cobra.Command{
		Use:   "unlock [file]",
		Short: "Unlock RSA PRIVATE KEY FILE",
		Long: `Decrypt a password protected RSA private key in place.

Pass a file and a password source to skip both prompts:
  gossl unlock server.key --password-file secret.txt
  GOSSL_PASSWORD=... gossl unlock server.key

There is deliberately no --password flag. A password on the command line
is visible to every other process through ps.

Without a file it lists the keys in the current directory and asks.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			var file string
			if len(args) == 1 {
				file = args[0]
			}
			return runUnlock(file, unlockPasswordFile)
		},
	}
)

func init() {
	unlockCommand.Flags().StringVar(&unlockPasswordFile, "password-file", "",
		"[optional] read the password from this file instead of asking")

	rootCmd.AddCommand(unlockCommand)
}

// resolvePassword 는 비대화형 입력원을 먼저 보고, 없으면 물어본다.
// 터미널이 없는데 입력원도 없으면 멈춰 있지 말고 실패한다.
func resolvePassword(passwordFile string) (string, error) {
	if passwordFile != "" {
		data, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", err
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}

	if password, ok := os.LookupEnv("GOSSL_PASSWORD"); ok {
		return password, nil
	}

	if !stdinIsTerminal() {
		return "", fmt.Errorf("no terminal to ask on, pass --password-file or set GOSSL_PASSWORD")
	}

	return internal.AskInput("What is your password", 1)
}

// runUnlock 은 암호가 걸린 RSA 개인키의 암호를 풀어 저장한다.
// file 이 비어 있으면 현재 디렉토리에서 고르게 한다.
func runUnlock(file, passwordFile string) error {
	_, fileName, err := resolveCertFile("Select RSA PRIVATE KEY File", file)
	if err != nil {
		return panicRed(err)
	}

	p, err := internal.GetPemType(fileName)
	if err != nil {
		return panicRed(err)
	}
	if p.Type != "RSA PRIVATE KEY" {
		return panicRed(fmt.Errorf("select only rsa private key file please"))
	}

	//nolint:staticcheck // SA1019: 레거시 RFC 1423 키 호환을 위해 유지
	if !x509.IsEncryptedPEMBlock(p.Block) {
		return panicRed(fmt.Errorf("this rsa private key file is not locked"))
	}

	password, err := resolvePassword(passwordFile)
	if err != nil {
		return panicRed(err)
	}

	//nolint:staticcheck // SA1019: 위와 동일
	der, err := x509.DecryptPEMBlock(p.Block, []byte(password))
	if err != nil {
		return panicRed(err)
	}

	if err := writeUnlockedKey(fileName, der); err != nil {
		return panicRed(err)
	}
	return nil
}
