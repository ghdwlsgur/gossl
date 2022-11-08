package internal

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

func Validate(domainName string) {
	url_i := url.URL{}
	url_proxy, err := url_i.Parse("https://sangdo-vod02.fastedge.net:443@61.110.198.20:443")

	if err != nil {
		os.Exit(1)
		fmt.Println(err)
	}

	// 5초 이내로 타임아웃 설정
	transport := http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// 프록시 설정
	transport.Proxy = http.ProxyURL(url_proxy)
	// SSL (TLS) 설정
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	conn, err := tls.Dial("tcp", "sangdo-vod02.fastedge.net:443", transport.TLSClientConfig)
	if err != nil {
		log.Println("Error in Dial")
		return
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if len(cert.DNSNames) > 0 {
			fmt.Printf("Issuer Name:\t%s\n", cert.Issuer)
			fmt.Printf("Common Name:\t%s\n", cert.Issuer.CommonName)
			fmt.Printf("Start Date:\t%s\n", cert.NotBefore.Format("2006-January-02"))
			fmt.Printf("Expire Date:\t%s\n", cert.NotAfter.Format("2006-January-02"))
		}
	}

	client := &http.Client{
		Transport: &transport,
	}

	resp, err := client.Get("http://sangdo-vod02.fastedge.net")

	if err != nil {
		fmt.Println(err)
	}
	fmt.Printf("%s\t\t%s\n", "Status:", resp.Status)
	fmt.Printf("%s\t\t%s\n", "Date:", resp.Header.Values("Date")[0])
	fmt.Printf("%s\t\t%s\n", "Server:", resp.Header.Values("Server")[0])
	fmt.Printf("%s\t%s\n", "Content-Type", resp.Header.Values("Content-Type")[0])
	fmt.Printf("%s\t%s\n", "Connection", resp.Header.Values("Connection")[0])
}
