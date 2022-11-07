package dig

import (
	"fmt"

	"github.com/lixiangzhong/dnsutil"
	"github.com/miekg/dns"
)

func main() {
	var dig dnsutil.Dig
	dig.SetDNS("1.1.1.1")
	msg, err := dig.GetMsg(dns.TypeA, "google.com")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(msg.Question)
	fmt.Println(msg.Answer)
	fmt.Println(msg.Ns)
	fmt.Println(msg.Extra)
}
