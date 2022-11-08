package main

import (
	"fmt"
	"net"
	"os"
)

func main() {
	// cmd.Execute("1.0")

	// domain := "sangdo-vod02.fastedge.net"
	// var dig dnsutil.Dig
	// rsps, err := dig.Trace(domain)

	// if err != nil {
	// 	fmt.Println(err)
	// 	return
	// }

	// for _, rsp := range rsps {
	// 	if rsp.Msg.Authoritative {
	// 		for _, answer := range rsp.Msg.Answer {
	// 			fmt.Println(strings.Split(answer.String(), " ")[1])
	// 		}
	// 	}
	// }

	ips, err := net.LookupIP("vod.ghu.ac.kr")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}
	for _, ip := range ips {
		fmt.Printf("%s\n", ip.String())
	}
}
