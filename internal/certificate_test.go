package internal

import (
	"crypto/tls"
	"fmt"
	"testing"

	"github.com/fatih/color"
)

func TestGetCertificate(t *testing.T) {

	ip := "185.199.110.153"
	domain := "ghdwlsgur.github.io"

	c := SetTransport(domain, ip)
	transport := c.transport

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", domain), transport.TLSClientConfig)
	if err != nil {
		t.Error(err)
	}
	defer conn.Close()

	for _, cert := range conn.ConnectionState().PeerCertificates {
		fmt.Printf("\n[%s]\n", color.HiWhiteString(DistinguishCertificateWithConnection(cert)))
		printCertifiacetInfo(cert)
	}
}
