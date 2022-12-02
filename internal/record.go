package internal

import "net"

func GetRecordIPv4(domainName string) ([]string, error) {

	ips, err := net.LookupIP(domainName)
	if err != nil {
		return nil, err
	}

	var ipList []string
	for _, ip := range ips {
		if net.ParseIP(ip.String()).To4() != nil {
			ipList = append(ipList, ip.String())
		}
	}

	return ipList, nil
}
