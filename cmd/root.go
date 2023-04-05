package cmd

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	which "github.com/hairyhenderson/go-which"
)

var (
	// PATH: /opt/homebrew/lib/gossl
	path = func() string {
		path := which.Which("gossl")
		path = strings.Replace(path, "bin", "lib", -1)
		return path
	}()

	// PATH: /opt/homebrew/lib/gossl/config.yaml
	_defaultYamlConfigPath = func(path, fileName string) string {
		return path + fileName
	}(path, "/config.yaml")
)

const (
	_configURL = "https://raw.githubusercontent.com/ghdwlsgur/gossl/master/config/rootSSL.yaml"
)

var (
	rootCmd = &cobra.Command{
		Use:   "gossl",
		Short: `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
		Long:  `gossl is an interactive tool that allows you to integrate certificates, look up certificates and private keys, split integrated certificate files by root, intermediate, and leaf certificates, or view certificate information applied to a domain by A record. We will update the certificate format that changes for each ca.`,
	}
)

func panicRed(err error) {
	fmt.Println(color.RedString("[err] %s", err.Error()))
	os.Exit(1)
}

func Execute(version string) {
	rootCmd.Version = version
	if err := rootCmd.Execute(); err != nil {
		panicRed(err)
	}
}

func configDownload() {
	if _, err := os.Stat(_defaultYamlConfigPath); errors.Is(err, os.ErrNotExist) {
		resp, err := http.Get(_configURL)
		if err != nil {
			panicRed(err)
		}
		defer resp.Body.Close()

		configFile, err := os.Create(_defaultYamlConfigPath)
		if err != nil {
			panicRed(err)
		}
		defer configFile.Close()

		_, err = io.Copy(configFile, resp.Body)
		if err != nil {
			panicRed(err)
		}
		fmt.Println(color.GreenString("SSL ROOT CERTIFICATE CONFIG FILE Download Complete"))
	}
}

func initConfig() {

	configDownload()

	args := os.Args[1:]
	_, _, err := rootCmd.Find(args)
	if err != nil {
		panicRed(err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
}
