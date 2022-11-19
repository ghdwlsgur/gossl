package internal

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Response struct {
	subject           pkix.Name
	subjectCommonName string
	certIssuerName    pkix.Name
	certCommonName    string
	certStartDate     string
	certExpireDate    string
	respStatus        string
	respDate          string
	respServer        string
	respContentType   string
	respConnection    string
	respCacheControl  string
}

func (r Response) getSubject() pkix.Name {
	return r.subject
}

func (r Response) getCertIssuerName() pkix.Name {
	return r.certIssuerName
}

func (r Response) getCertCommonName() string {
	return r.certCommonName
}

func (r Response) getCertStartDate() string {
	return r.certStartDate
}

func (r Response) getCertExpireDate() string {
	return r.certExpireDate
}

func (r Response) getRespStatus() string {
	return r.respStatus
}

func (r Response) getRespDate() string {
	return r.respDate
}

func (r Response) getRespServer() string {
	return r.respServer
}

func (r Response) getRespContentType() string {
	return r.respContentType
}

func (r Response) getRespConnection() string {
	return r.respConnection
}

func (r Response) getRespCacheControl() string {
	return r.respCacheControl
}

/* The following commands are implemented in code.
"echo | openssl s_client -showcerts -connect [ProxyIP]:[Port] -servername [Domain]"
"curl -vo /dev/null -H 'Range:bytes=0-1' --resolve '[Domain]:[Port]:[ProxyIP]' 'https://[Domain]"
*/

// This means it can be used as an alternative to the command
// Connect to requestDomain from the edge server of the domain passed as an argument.
func GetCertificateOnTheProxy(ips []net.IP, domain string, requestDomain string) (*Response, error) {

	res := &Response{}
	var ipList []string
	ipList = make([]string, 0, len(ips))
	for _, ip := range ips {
		ipList = append(ipList, ip.String())
	}

	message := fmt.Sprintf("Select %s A record", domain)
	answer, err := AskSelect(message, ipList)
	if err != nil {
		return nil, err
	}

	// The default connection is https.
	ref := fmt.Sprintf("https://%s:443@%s:443", domain, answer)
	url_i := url.URL{}

	// url_proxy, err := url_i.Parse("https://[Domain]:[Port]@[ProxyIP]:[Port]")
	url_proxy, err := url_i.Parse(ref)
	if err != nil {
		return nil, err
	}

	// Set timeout within 5 seconds
	transport := http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	// Set Proxy
	transport.Proxy = http.ProxyURL(url_proxy)

	// Set tls Configuration
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	dialAddr := fmt.Sprintf("%s:443", domain)

	// conn, err := tls.Dial("tcp", "[Domain]:[Port]", transport.TLSClientConfig)
	conn, err := tls.Dial("tcp", dialAddr, transport.TLSClientConfig)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	for _, cert := range certs {
		if len(cert.DNSNames) > 0 {

			res.subject = cert.Subject
			res.subjectCommonName = cert.Subject.CommonName
			res.certIssuerName = cert.Issuer
			res.certCommonName = cert.Issuer.CommonName
			res.certStartDate = cert.NotBefore.Format("2006-January-02")
			res.certExpireDate = cert.NotAfter.Format("2006-January-02")

			h := fmt.Sprintf("%s", cert.VerifyHostname(""))
			hl := strings.Split(h, ",")

			fmt.Printf("VerifyHostName %s\n", hl[:len(hl)-1])
			fmt.Printf("Subject\t\t%s\n", res.getSubject())
			fmt.Printf("Issuer Name\t%s\n", res.getCertIssuerName())
			fmt.Printf("Common Name\t%s\n", res.getCertCommonName())
			fmt.Printf("Start Date\t%s\n", res.getCertStartDate())
			fmt.Printf("Expire Date\t%s\n", color.HiGreenString(res.getCertExpireDate()))
		}
	}

	client := &http.Client{
		Transport: &transport,
	}

	url := fmt.Sprintf("http://%s", requestDomain)
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	resp.Header.Add("Range", "bytes: 0-1")
	res.respStatus = resp.Status

	headerField := []string{"Date", "Server", "Content-Type", "Connection", "Cache-Control"}

	for _, directive := range headerField {
		if fieldCheck := len(resp.Header.Values(directive)); fieldCheck > 0 {

			switch directive {
			case "Date":
				res.respDate = resp.Header.Values(directive)[0]
			case "Server":
				res.respServer = resp.Header.Values(directive)[0]
			case "Content-Type":
				res.respContentType = resp.Header.Values(directive)[0]
			case "Connection":
				res.respConnection = resp.Header.Values(directive)[0]
			case "Cache-Control":
				res.respCacheControl = resp.Header.Values(directive)[0]
			}
		}
	}

	if res.getRespStatus()[0:1] == "5" {
		fmt.Printf("%s\t\t%s\n", "Status", color.HiRedString(res.getRespStatus()))
	} else if res.getRespStatus()[0:1] == "4" {
		fmt.Printf("%s\t\t%s\n", "Status", color.HiYellowString(res.getRespStatus()))
	} else {
		fmt.Printf("%s\t\t%s\n", "Status", color.HiGreenString(res.getRespStatus()))
	}

	fmt.Printf("%s\t\t%s\n", "Date", res.getRespDate())
	fmt.Printf("%s\t\t%s\n", "Server", color.HiGreenString(res.getRespServer()))
	fmt.Printf("%s\t%s\n", "Content-Type", res.getRespContentType())
	fmt.Printf("%s\t%s\n", "Connection", res.getRespConnection())
	fmt.Printf("%s\t%s\n", "Cache-Control", res.getRespCacheControl())

	return &Response{
		certIssuerName:  res.certIssuerName,
		certCommonName:  res.certCommonName,
		certStartDate:   res.certStartDate,
		certExpireDate:  res.certExpireDate,
		respStatus:      res.respStatus,
		respDate:        res.respDate,
		respServer:      res.respServer,
		respContentType: res.respContentType,
		respConnection:  res.respConnection,
	}, nil

}

func DistinguishCertificate(p *Pem, c *CertFile) (string, error) {

	cert, err := x509.ParseCertificate(p.Block.Bytes)
	if err != nil {
		return "", err
	}

	if cert.IsCA {

		if cert.Subject.String() == cert.Issuer.String() {
			return "Root Certificate", nil
		} else {
			return "Intermediate Certificate", nil
		}

	}

	if c.Extension == "crt" || c.Extension == "pem" {
		return "Leaf Certificate", nil
	}

	return "Unknown", nil
}
