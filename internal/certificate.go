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

// ! curl
// curl -vo /dev/null -H 'Range:bytes=0-1' --resolve 'naver.com:443:223.130.195.95' 'https://www.naver.com/include/themecast/targetAndPanels.json'

// ! gossl
// gossl connect -n naver.com -t naver.com/include/themecast/targetAndPanels.json

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
			res.certStartDate = cert.NotBefore.Format("2006-01-02")
			res.certExpireDate = cert.NotAfter.Format("2006-01-02")

			h := fmt.Sprintf("%s", cert.VerifyHostname(""))
			hl := strings.Split(h, ",")

			now, _ := time.Parse("2006-01-02", time.Now().Format("2006-01-02"))
			expireDate, _ := time.Parse("2006-01-02", res.getCertExpireDate())

			var colorDays string
			days := int32(expireDate.Sub(now).Hours() / 24)
			if days < 30 {
				colorDays = color.HiRedString(fmt.Sprintf("[%v days]", days))
			} else {
				colorDays = color.HiGreenString(fmt.Sprintf("[%v days]", days))
			}

			fmt.Printf("\n%s\n", color.HiWhiteString("Certificate"))
			fmt.Printf("%s\t%s\n",
				color.HiBlackString("Verify Host"),
				strings.TrimSpace(strings.Split(hl[:len(hl)-1][0], ":")[1]))

			printSplitFunc(res.getSubject().String(), "Subject")
			printSplitFunc(res.getCertIssuerName().String(), "Issuer Name")

			printFunc("Common Name", res.getCertCommonName())
			printFunc("Start Date", res.getCertStartDate())
			fmt.Printf("%s\t%s %s\n",
				color.HiBlackString("Expire Date"),
				color.HiGreenString(res.getCertExpireDate()), colorDays)
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

	statusCode := res.getRespStatus()[0:1]
	if statusCode == "5" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiRedString(res.getRespStatus()))
	} else if statusCode == "4" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiYellowString(res.getRespStatus()))
	} else {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiGreenString(res.getRespStatus()))
	}

	printFunc("Date", res.getRespDate())
	printFunc("Server", res.getRespServer())
	printFunc("Content-Type", res.getRespContentType())
	printFunc("Connection", res.getRespConnection())
	printFunc("Cache-Control", res.getRespCacheControl())
	fmt.Println()

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

func printSplitFunc(word, field string) {
	for i, n := range strings.Split(word, ",") {
		if i == 0 {
			printFunc(field, n)
		} else {
			fmt.Printf("\t\t%s\n", n)
		}
	}
}

func printFunc(field, value string) {
	if len(field) < 8 {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString(field), value)
	} else {
		fmt.Printf("%s\t%s\n", color.HiBlackString(field), value)
	}
}
