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
		Run: func(cmd *cobra.Command, args []string) {
			var (
				certFile *internal.CertFile
				p        *internal.Pem
				err      error
			)

			if err = cobra.NoArgs(cmd, args); err != nil {
				panicRed(err)
			}

			certFile, err = internal.DirGrepX509()
			if err != nil {
				panicRed(err)
			}

			fileName, err := internal.AskSelect("Select RSA PRIVATE KEY File", certFile.Name)
			if err != nil {
				panicRed(err)
			}

			p, err = internal.GetPemType(fileName)
			if err != nil {
				panicRed(err)
			}

			if p.Type != "RSA PRIVATE KEY" {
				panicRed(fmt.Errorf("select only rsa private key file please"))
			}

			block := p.Block
			isEncrypted := x509.IsEncryptedPEMBlock(block)

			if isEncrypted {
				password, err := internal.AskInput("What is your password", 1)
				if err != nil {
					panicRed(err)
				}

				b, err := x509.DecryptPEMBlock(block, []byte(password))
				if err != nil {
					panicRed(err)
				}

				if err := writeUnlockedKey(fileName, b); err != nil {
					panicRed(err)
				}

			} else {
				panicRed(fmt.Errorf("this rsa private key file is not locked"))
			}
		},
	}
)

func init() {
	rootCmd.AddCommand(unlockCommand)
}
