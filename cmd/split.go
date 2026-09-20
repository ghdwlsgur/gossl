package cmd

import (
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/ghdwlsgur/gossl/internal"
	"github.com/spf13/cobra"
)

// classifiedBlocks 는 통합 인증서를 종류별로 나눈 결과다.
type classifiedBlocks struct {
	leaf         []*pem.Block
	intermediate []*pem.Block
	root         []*pem.Block

	// 체인 연결을 확인하려고 각 인증서의 [Subject CN, Issuer CN] 을 모은다.
	leafSubIss         []string
	intermediateSubIss []string
	rootSubIss         []string
}

// classifyBlocks 는 PEM 데이터를 읽어 leaf, intermediate, root 로 나눈다.
// 파일이나 사용자 입력에 의존하지 않는 순수 함수다.
func classifyBlocks(data []byte) (*classifiedBlocks, error) {
	c := &classifiedBlocks{}

	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}

		detail, err := internal.DistinguishCertificate(&internal.Pem{Block: block}, nil, 1)
		if err != nil {
			return nil, err
		}
		fmt.Printf("\t ➕ %s\n", color.HiWhiteString(detail))

		subIss, err := internal.GetSubjectCNandIssuerCN(block)
		if err != nil {
			return nil, err
		}

		switch strings.Fields(detail)[0] {
		case "Leaf":
			c.leaf = append(c.leaf, block)
			c.leafSubIss = append(c.leafSubIss, subIss...)
		case "Intermediate":
			c.intermediate = append(c.intermediate, block)
			c.intermediateSubIss = append(c.intermediateSubIss, subIss...)
		case "Root":
			c.root = append(c.root, block)
			c.rootSubIss = append(c.rootSubIss, subIss...)
		}
	}

	return c, nil
}

// chainLinked 는 앞 인증서의 Issuer CN 과 뒤 인증서의 Subject CN 이
// 이어지는지 본다. 한쪽이 비어 있으면 판단하지 않는다.
func chainLinked(lower, upper []string) (linked bool, comparable bool) {
	if len(lower) == 0 || len(upper) == 0 {
		return false, false
	}
	return lower[len(lower)-1] == upper[0], true
}

// printChainReport 는 체인이 이어지는지 사람이 읽을 형태로 출력한다.
func printChainReport(c *classifiedBlocks) {
	report := func(label string, lower, upper []string) {
		linked, ok := chainLinked(lower, upper)
		if !ok {
			return
		}
		status := color.HiRedString("Not Matched")
		if linked {
			status = color.HiMagentaString("Matched")
		}
		fmt.Printf("%s %s\n", color.HiBlackString(label), status)
	}

	fmt.Println()
	report("Leaf:[Issuer CN] Intermediate:[Subject CN]", c.leafSubIss, c.intermediateSubIss)
	report("Intermediate:[Issuer CN] Root:[Subject CN]", c.intermediateSubIss, c.rootSubIss)
}

// writeBlocks 는 블록들을 gossl_<종류>_<번호>.crt 로 저장한다.
func writeBlocks(blocks []*pem.Block, typeName string) error {
	for i, block := range blocks {
		fileName := fmt.Sprintf("gossl_%s_%d.crt", typeName, i+1)

		f, err := os.Create(fileName)
		if err != nil {
			return err
		}
		if err := pem.Encode(f, block); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		fmt.Printf("📄 %s %s\n", color.HiGreenString(fileName), "created successfully")
	}
	return nil
}

// splittableFiles 는 현재 디렉토리에서 블록이 2개 이상인 파일만 고른다.
func splittableFiles() ([]string, error) {
	certFile, err := internal.DirGrepX509()
	if err != nil {
		return nil, err
	}

	var list []string
	for _, name := range certFile.Name {
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, err
		}
		if n := internal.CountPemBlock(data); n > 1 {
			list = append(list, fmt.Sprintf("%s [in %d Block]", name, n))
		}
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("a certificate file with pem block length greater than 2 does not exist")
	}
	return list, nil
}

// runSplit 은 통합 인증서를 종류별로 나눈다.
// showOnly 면 구성만 보여주고 파일은 만들지 않는다.
func runSplit(showOnly bool) error {
	selectList, err := splittableFiles()
	if err != nil {
		return panicRed(err)
	}

	selected, err := internal.AskSelect("Select Certificate File", selectList)
	if err != nil {
		return panicRed(err)
	}
	file := strings.TrimSpace(strings.Split(selected, "[")[0])

	data, err := os.ReadFile(file)
	if err != nil {
		return panicRed(err)
	}

	fmt.Printf("✅ %s\n", color.HiGreenString(file))
	c, err := classifyBlocks(data)
	if err != nil {
		return panicRed(err)
	}

	if showOnly {
		printChainReport(c)
		return nil
	}

	fmt.Printf("\n%s\n", color.HiWhiteString("Created Files"))
	for _, g := range []struct {
		blocks []*pem.Block
		name   string
	}{
		{c.leaf, "leaf"},
		{c.intermediate, "intermediate"},
		{c.root, "root"},
	} {
		if err := writeBlocks(g.blocks, g.name); err != nil {
			return panicRed(err)
		}
	}
	return nil
}

var (
	splitCommand = &cobra.Command{
		Use:   "split",
		Short: "Split Unified Certificate.",
		Long:  "Split Unified Certificate.",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 && (args[0] != "show" || len(args) > 1) {
				return panicRed(fmt.Errorf("input format is incorrect. ex) gossl split show"))
			}
			return runSplit(len(args) > 0 && args[0] == "show")
		},
	}
)

func init() {
	rootCmd.AddCommand(splitCommand)
}
