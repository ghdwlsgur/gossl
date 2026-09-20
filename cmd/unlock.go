package cmd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

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
	unlockCommand = &cobra.Command{
		Use:   "unlock",
		Short: "Unlock RSA PRIVATE KEY FILE",
		Long:  "Unlock RSA PRIVATE KEY FILE",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cobra.NoArgs(cmd, args); err != nil {
				return panicRed(err)
			}
			return runUnlock()
		},
	}
)

func init() {
	rootCmd.AddCommand(unlockCommand)
}

// runUnlock 은 암호가 걸린 RSA 개인키를 골라 암호를 풀어 저장한다.
func runUnlock() error {
	certFile, err := internal.DirGrepX509()
	if err != nil {
		return panicRed(err)
	}

	fileName, err := internal.AskSelect("Select RSA PRIVATE KEY File", certFile.Name)
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

	password, err := internal.AskInput("What is your password", 1)
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
