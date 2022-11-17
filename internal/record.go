package internal

import "net"

func GetRecord(domainName string) ([]net.IP, error) {

	ips, err := net.LookupIP(domainName)
	if err != nil {
		return nil, err
	}

	return ips, nil
}
