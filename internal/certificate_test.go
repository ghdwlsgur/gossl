package internal

import (
	"crypto/tls"
	"fmt"
	"testing"
)

func TestGetCertificate(t *testing.T) {

	ip := "185.199.110.153"
	domain := "ghdwlsgur.github.io"

	transport := SetTransport(domain, ip)

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		fmt.Println(cert.DNSNames)

	}
}
