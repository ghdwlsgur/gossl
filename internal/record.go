package internal

import "net"

func GetRecord(domainName string) ([]net.IP, error) {
	// ips, err := net.LookupIP("vod.ghu.ac.kr")
	ips, err := net.LookupIP(domainName)
	if err != nil {
		return nil, err
	}
	// for _, ip := range ips {
	// 	fmt.Printf("%s\n", ip.String())
	// }
	return ips, nil
}
