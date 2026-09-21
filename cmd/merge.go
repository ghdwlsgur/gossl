package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// collectForMerge 는 고른 파일들을 읽어 종류별 블록으로 모은다.
// allowPrivateKey 가 거짓이면 개인키가 섞인 파일을 거부한다.
func collectForMerge(files []string, allowPrivateKey bool) (leaf, intermediate, root, private []*pem.Block, err error) {
	for _, name := range files {
		data, readErr := os.ReadFile(name)
		if readErr != nil {
			return nil, nil, nil, nil, readErr
		}

		first, _ := pem.Decode(data)
		if first == nil {
			return nil, nil, nil, nil, fmt.Errorf("%s is empty", name)
		}

		if isPrivateKeyBlock(first.Type) {
			if !allowPrivateKey {
				return nil, nil, nil, nil, fmt.Errorf("please select only the certificate file")
			}
			private = append(private, first)
			continue
		}

		blockCount := internal.CountPemBlock(data)
		detail, distErr := internal.DistinguishCertificate(&internal.Pem{Block: first}, nil, blockCount)
		if distErr != nil {
			return nil, nil, nil, nil, distErr
		}

		kind := strings.Fields(detail)[0]
		if kind == "Unified" {
			return nil, nil, nil, nil, fmt.Errorf("%s is already merged certificate file, please choose another file", name)
		}

		for {
			var block *pem.Block
			block, data = pem.Decode(data)
			if block == nil {
				break
			}
			switch kind {
			case "Leaf":
				leaf = append(leaf, block)
			case "Intermediate":
				intermediate = append(intermediate, block)
			case "Root":
				root = append(root, block)
			}
		}
	}
	return leaf, intermediate, root, private, nil
}

// isPrivateKeyBlock 은 PEM 타입이 개인키인지 본다.
// RSA PRIVATE KEY 뿐 아니라 PKCS#8 과 EC 형식도 잡는다.
func isPrivateKeyBlock(pemType string) bool {
	return strings.HasSuffix(pemType, "PRIVATE KEY")
}

// writeMerged 는 leaf, intermediate, root, 개인키 순으로 한 파일에 쓴다.
func writeMerged(path string, groups ...[]*pem.Block) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, group := range groups {
		for _, block := range group {
			if err := pem.Encode(file, block); err != nil {
				return err
			}
		}
	}
	return file.Close()
}

// selectForMerge 는 합칠 파일 목록을 정한다.
// 인자로 받았으면 프롬프트를 띄우지 않는다.
func selectForMerge(files []string) ([]string, error) {
	if len(files) > 0 {
		for _, name := range files {
			if err := statCertFile(name); err != nil {
				return nil, err
			}
		}
		return files, nil
	}

	certFile, err := internal.DirGrepX509()
	if err != nil {
		return nil, err
	}
	return internal.AskMultiSelect("Select Certificate File", certFile.Name)
}

// runMerge 는 고른 인증서들을 신뢰 체인 순서로 하나의 파일에 합친다.
// files 가 비어 있으면 현재 디렉토리에서 고르게 한다.
func runMerge(files []string, requestedName string, allowPrivateKey bool) error {
	newFile := outputName(requestedName, "gossl_merge_output", ".pem")

	selectList, err := selectForMerge(files)
	if err != nil {
		return panicRed(err)
	}
	if n := len(selectList); n < 2 {
		return panicRed(fmt.Errorf("please select at least 2"))
	} else if n > 4 {
		return panicRed(fmt.Errorf("please select up to 4"))
	}

	leaf, intermediate, root, private, err := collectForMerge(selectList, allowPrivateKey)
	if err != nil {
		return panicRed(err)
	}

	if err := writeMerged(newFile, leaf, intermediate, root, private); err != nil {
		return panicRed(err)
	}

	fmt.Printf(color.HiGreenString("📄 %s created successfully\n"), newFile)
	return nil
}

var (
	mergeCommand = &cobra.Command{
		Use:   "merge [file...]",
		Short: "Combine each certificate file in order of leaf, intermediate, root.",
		Long: `Combine certificate files in order of leaf, intermediate, root.

Pass the files to skip the prompt, which is what you want in a pipeline:
  gossl merge leaf.pem chain.pem -n bundle
  gossl merge leaf.pem chain.pem server.key -f

Without files it lists the certificates in the current directory and asks.
Takes 2 to 4 files either way.`,
		Args: cobra.MaximumNArgs(4),
		RunE: func(_ *cobra.Command, args []string) error {
			return runMerge(args, viper.GetString("pem-file-name"), viper.GetBool("add-private-key"))
		},
	}
)

func init() {
	mergeCommand.Flags().StringP("name", "n", "", "[optional] Enter the file name to create.")
	mergeCommand.Flags().BoolP("force", "f", false, "[optional] merge key file and certificate file")

	viper.BindPFlag("pem-file-name", mergeCommand.Flags().Lookup("name"))
	viper.BindPFlag("add-private-key", mergeCommand.Flags().Lookup("force"))

	rootCmd.AddCommand(mergeCommand)
}
