package internal

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/AlecAivazis/survey/v2"
)

// var (
// 	_response *Response
// )

// type (
// 	Response struct {
// 		certIssuerName pkix.Name
// 		certCommonName string
// 		certStartDate   string
// 		certExpireDate string
// 		respStatus      string
// 		respDate        string
// 		respServer      string
// 		respContentType string
// 		respConnection  string
// 	}
// )

// (*Response, error)
func Validate(ips []net.IP, domainName string) {

	var ipList []string
	ipList = make([]string, 0, len(ips))
	for _, ip := range ips {
		ipList = append(ipList, ip.String())
	}

	prompt := &survey.Select{
		Message: "choose ip",
		Options: ipList,
	}

	answer := ""
	if err := survey.AskOne(prompt, &answer, survey.WithIcons(func(icons *survey.IconSet) {
		icons.SelectFocus.Format = "green+hb"
	}), survey.WithPageSize(len(ipList))); err != nil {
		// return nil, err
		fmt.Println(err)
	}

	ref := fmt.Sprintf("https://%s:443@%s:443", domainName, answer)
	url_i := url.URL{}

	// url_proxy, err := url_i.Parse("https://sangdo-vod02.fastedge.net:443@61.110.198.20:443")
	url_proxy, err := url_i.Parse(ref)
	if err != nil {
		// return nil, err
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

	dialAddr := fmt.Sprintf("%s:443", domainName)

	// conn, err := tls.Dial("tcp", "sangdo-vod02.fastedge.net:443", transport.TLSClientConfig)
	conn, err := tls.Dial("tcp", dialAddr, transport.TLSClientConfig)
	if err != nil {
		fmt.Println("check")
		// return nil, err
		fmt.Println(err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	for _, cert := range certs {
		if len(cert.DNSNames) > 0 {
			// _response.certIssuerName = cert.Issuer
			// return &Response{
			// 	certIssuerName: cert.Issuer,
			// 	certCommonName: cert.Issuer.CommonName,
			// 	certExpireDate: cert.NotBefore.Format("2006-January-02"),
			// }, nil
			// _response.certCommonName = cert.Issuer.CommonName
			// _response.certStartDate = cert.NotBefore.Format("2006-January-02")
			// _response.certExpireDate = cert.NotAfter.Format("2006-January-02")

			fmt.Printf("Issuer Name:\t%s\n", cert.Issuer)
			fmt.Printf("Common Name:\t%s\n", cert.Issuer.CommonName)
			fmt.Printf("Start Date:\t%s\n", cert.NotBefore.Format("2006-January-02"))
			fmt.Printf("Expire Date:\t%s\n", cert.NotAfter.Format("2006-January-02"))
			// &Response.certIssuerName = cert.Issuer

			// Response.certIssuerName = cert.Issuer
			// &Response{
			// 	certIssuerName: cert.Issuer,
			// }

			// &Response{
			// 	certIssuerName: cert.Issuer,
			// 	certCommonName: cert.Issuer.CommonName,
			// 	certStartDate:  cert.NotBefore.Format("2006-January-02"),
			// 	certExpireDate: cert.NotAfter.Format("2006-January-02"),
			// }
		}
	}
	// return &Response{}

	client := &http.Client{
		Transport: &transport,
	}

	url := fmt.Sprintf("http://%s", domainName)
	// resp, err := client.Get("http://sangdo-vod02.fastedge.net")
	resp, err := client.Get(url)
	if err != nil {
		// return nil, err
		fmt.Println(err)
	}

	// _response.respStatus = resp.Status
	// _response.respDate = resp.Header.Values("Date")[0]
	// _response.respServer = resp.Header.Values("Server")[0]
	// _response.respContentType = resp.Header.Values("Content-Type")[0]
	// _response.respConnection = resp.Header.Values("Connection")[0]

	fmt.Printf("%s\t\t%s\n", "Status:", resp.Status)
	fmt.Printf("%s\t\t%s\n", "Date:", resp.Header.Values("Date")[0])
	fmt.Printf("%s\t\t%s\n", "Server:", resp.Header.Values("Server")[0])
	fmt.Printf("%s\t%s\n", "Content-Type", resp.Header.Values("Content-Type")[0])
	fmt.Printf("%s\t%s\n", "Connection", resp.Header.Values("Connection")[0])

	// return _response, nil
	// // return &Response{
	// // 	respStatus: resp.Status,
	// // 	respDate: resp.Header.Values("Date")[0],
	// // 	respServer: resp.Header.Values("Server")[0],
	// // 	respContentType: resp.Header.Values("Content-Type")[0],
	// // 	resConnection: resp.Header.Values("Connection")[0],
	// // }, nil
}
