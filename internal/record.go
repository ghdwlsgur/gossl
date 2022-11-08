package internal

import (
	"fmt"
	"net"
	"os"
)

func GetRecord(domainName string) {
	ips, err := net.LookupIP("vod.ghu.ac.kr")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf("%s\n", ip.String())
	}
}
