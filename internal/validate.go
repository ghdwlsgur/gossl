package internal

import (
	"crypto/tls"
	"crypto/x509/pkix"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/AlecAivazis/survey/v2"
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

func Validate(ips []net.IP, domainName string, reqDomainName string) (*Response, error) {

	res := &Response{}
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
		return nil, err
	}

	ref := fmt.Sprintf("https://%s:443@%s:443", domainName, answer)
	url_i := url.URL{}

	// url_proxy, err := url_i.Parse("https://sangdo-vod02.fastedge.net:443@61.110.198.20:443")
	url_proxy, err := url_i.Parse(ref)
	if err != nil {
		return nil, err
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

			// fmt.Println(cert.VerifyHostname(""))
			fmt.Printf("Subject:\t%s\n", res.getSubject())
			fmt.Printf("Issuer Name:\t%s\n", res.getCertIssuerName())
			fmt.Printf("Common Name:\t%s\n", res.getCertCommonName())
			fmt.Printf("Start Date:\t%s\n", res.getCertStartDate())
			fmt.Printf("Expire Date:\t%s\n", color.HiGreenString(res.getCertExpireDate()))

		}
	}

	client := &http.Client{
		Transport: &transport,
	}

	url := fmt.Sprintf("http://%s", reqDomainName)
	// resp, err := client.Get("http://sangdo-vod02.fastedge.net")
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}

	res.respStatus = resp.Status
	res.respDate = resp.Header.Values("Date")[0]
	res.respServer = resp.Header.Values("Server")[0]
	res.respContentType = resp.Header.Values("Content-Type")[0]
	res.respConnection = resp.Header.Values("Connection")[0]

	fmt.Printf("%s\t\t%s\n", "Status:", res.getRespStatus())
	fmt.Printf("%s\t\t%s\n", "Date:", res.getRespDate())
	fmt.Printf("%s\t\t%s\n", "Server:", color.HiGreenString(res.getRespServer()))
	fmt.Printf("%s\t%s\n", "Content-Type", res.getRespContentType())
	fmt.Printf("%s\t%s\n", "Connection", res.getRespConnection())

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
