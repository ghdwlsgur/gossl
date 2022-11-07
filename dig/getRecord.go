package dig

import (
	"fmt"
	"strings"

	"github.com/lixiangzhong/dnsutil"
)

func getRecord(domainName string) {
	domain := domainName
	var dig dnsutil.Dig
	rsps, err := dig.Trace(domain)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, rsp := range rsps {
		if rsp.Msg.Authoritative {
			for _, answer := range rsp.Msg.Answer {
				fmt.Println(strings.Split(answer.String(), " ")[1])
			}
		}
	}
}
