package internal

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/fatih/color"
	"github.com/tcnksm/go-httpstat"
)

type Stat struct {
	DnsLookup         string
	TcpConnection     string
	TlsHandshake      string
	ServerProcessing  string
	ContentTransfer   string
	Total             string
	CumulativeTcp     string
	CumulativeTls     string
	CumulativeServer  string
	CumulativeContent string
	Ipv4              string
}

type Request struct {
	hostField  string
	rangeField string
}

func (r Request) getHost() string {
	return r.hostField
}

func (r Request) getRange() string {
	return r.rangeField
}

func HTTPResponseStat(ip string, targetUrl, targetUrlHost string, target string, port int, host string) error {

	ref := fmt.Sprintf("http://%s:%v@%s:%v", targetUrlHost, port, ip, port)

	netUrl := url.URL{}
	url_proxy, err := netUrl.Parse(ref)
	if err != nil {
		return err
	}

	transport := http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	transport.Proxy = http.ProxyURL(url_proxy)

	client := &http.Client{
		Transport: &transport,
	}

	urlDomain := fmt.Sprintf("http://%s", targetUrl)
	req, err := http.NewRequest("GET", urlDomain, nil)
	if err != nil {
		panic(err)
	}

	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)
	req = req.WithContext(ctx)

	req.Header.Add("Range", "bytes=0-1")
	if host != "" {
		req.Header.Add("Host", host)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	stat := &Stat{}
	end := time.Now()

	dnsLookup := int(result.DNSLookup / time.Millisecond)
	tcpConnection := int(result.TCPConnection / time.Millisecond)
	serverProcessing := int(result.ServerProcessing / time.Millisecond)

	stat.DnsLookup = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup))
	stat.TcpConnection = color.HiMagentaString(fmt.Sprintf("%dms", tcpConnection))
	stat.ServerProcessing = color.HiMagentaString(fmt.Sprintf("%dms", serverProcessing))
	stat.ContentTransfer = color.HiMagentaString(fmt.Sprintf("%dms", int(result.ContentTransfer(end)/time.Millisecond)))
	stat.CumulativeTcp = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup+tcpConnection))
	stat.CumulativeServer = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup+tcpConnection+serverProcessing))
	stat.CumulativeContent = color.HiMagentaString(fmt.Sprintf("%v", result.Total(end)/time.Millisecond))
	stat.Ipv4 = ip

	const httpTmpl = "\tDNS Lookup:\t\t{{.DnsLookup}}\n\tTCP Connection:\t\t{{.TcpConnection}}\t\t\t\t{{.CumulativeTcp}}\n\tServer Processing:\t{{.ServerProcessing}}\t\t\t\t{{.CumulativeServer}}\n\tContent Transfer:\t{{.ContentTransfer}}\t\t\t{{.CumulativeContent}}\n\n"
	t, err := template.New("monitor").Parse(httpTmpl)
	if err != nil {
		return err
	}

	fmt.Printf("\n\t==============%s [%s]==============\n", color.HiYellowString(target), color.HiYellowString(stat.Ipv4))
	fmt.Printf("\n%s\n", color.HiWhiteString("Trace HTTP Latency"))
	err = t.Execute(os.Stdout, stat)
	if err != nil {
		return err
	}

	reqDirective := &Request{}
	if len(resp.Request.Header.Values("host")) > 0 {
		reqDirective.hostField = resp.Request.Header.Values("host")[0] // [optional]
	}
	reqDirective.rangeField = resp.Request.Header.Values("range")[0] // [required]

	res := &Response{}
	res.respStatus = resp.Status

	fmt.Printf("%s\n", color.HiWhiteString("Request Headers"))
	fmt.Printf("%s\t\t%s\n", color.HiBlackString("Host"), reqDirective.getHost())
	fmt.Printf("%s\t\t%s\n\n", color.HiBlackString("Range"), reqDirective.getRange())

	fmt.Printf("%s\n", color.HiWhiteString("Response Headers"))
	if res.getRespStatus()[0:1] == "5" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiRedString(res.getRespStatus()))
	} else if res.getRespStatus()[0:1] == "4" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiYellowString(res.getRespStatus()))
	} else {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiGreenString(res.getRespStatus()))
	}

	for directive, value := range resp.Header {
		length := len(directive)

		if length > 14 {
			var prefixBucket []string
			words := strings.Split(directive, "-")
			for i, word := range words {
				if i != len(words)-1 {
					prefixBucket = append(prefixBucket, word[:1])
				}
			}

			front := strings.Join(prefixBucket, "")
			directiveFormat := strings.Join([]string{front, words[len(words)-1]}, "-")
			fmt.Printf("%s\t%s\n", color.HiBlackString(directiveFormat), value[0])
		} else if length < 8 {
			fmt.Printf("%s\t\t%s\n", color.HiBlackString(directive), value[0])
		} else {
			fmt.Printf("%s\t%s\n", color.HiBlackString(directive), value[0])
		}
	}
	fmt.Println()

	return nil
}

func HTTPSResponseStat(ip string, targetUrl, targetUrlHost string, target string, host string) error {

	ref := fmt.Sprintf("https://%s:443@%s:443", targetUrlHost, ip)
	netUrl := url.URL{}

	url_proxy, err := netUrl.Parse(ref)
	if err != nil {
		return err
	}

	transport := http.Transport{
		Dial: (&net.Dialer{
			Timeout: 5 * time.Second,
		}).Dial,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	transport.Proxy = http.ProxyURL(url_proxy)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	dialAddr := fmt.Sprintf("%s:443", targetUrlHost)
	conn, err := tls.Dial("tcp", dialAddr, transport.TLSClientConfig)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := &http.Client{
		Transport: &transport,
	}

	urlDomain := fmt.Sprintf("http://%s", targetUrl)
	req, err := http.NewRequest("GET", urlDomain, nil)
	if err != nil {
		panic(err)
	}

	var result httpstat.Result
	ctx := httpstat.WithHTTPStat(req.Context(), &result)
	req = req.WithContext(ctx)

	req.Header.Add("Range", "bytes=0-1")
	if host != "" {
		req.Header.Add("Host", host)
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	stat := &Stat{}
	end := time.Now()

	dnsLookup := int(result.DNSLookup / time.Millisecond)
	tcpConnection := int(result.TCPConnection / time.Millisecond)
	tlsHandShake := int(result.TLSHandshake / time.Millisecond)
	serverProcessing := int(result.ServerProcessing / time.Millisecond)

	stat.DnsLookup = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup))
	stat.TcpConnection = color.HiMagentaString(fmt.Sprintf("%dms", tcpConnection))
	stat.TlsHandshake = color.HiMagentaString(fmt.Sprintf("%dms", tlsHandShake))
	stat.ServerProcessing = color.HiMagentaString(fmt.Sprintf("%dms", serverProcessing))
	stat.ContentTransfer = color.HiMagentaString(fmt.Sprintf("%dms", int(result.ContentTransfer(end)/time.Millisecond)))
	stat.CumulativeTcp = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup+tcpConnection))
	stat.CumulativeTls = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup+tcpConnection+tlsHandShake))
	stat.CumulativeServer = color.HiMagentaString(fmt.Sprintf("%dms", dnsLookup+tcpConnection+tlsHandShake+serverProcessing))
	stat.CumulativeContent = color.HiMagentaString(fmt.Sprintf("%v", result.Total(end)/time.Millisecond))
	stat.Ipv4 = ip

	const httpsTmpl = "\tDNS Lookup:\t\t{{.DnsLookup}}\n\tTCP Connection:\t\t{{.TcpConnection}}\t\t\t\t{{.CumulativeTcp}}\n\tTLS Handshake:\t\t{{.TlsHandshake}}\t\t\t\t{{.CumulativeTls}}\n\tServer Processing:\t{{.ServerProcessing}}\t\t\t\t{{.CumulativeServer}}\n\tContent Transfer:\t{{.ContentTransfer}}\t\t\t{{.CumulativeContent}}\n\n"

	t, err := template.New("monitor").Parse(httpsTmpl)
	if err != nil {
		return err
	}

	fmt.Printf("\n\t==============%s [%s]==============\n", color.HiYellowString(target), color.HiYellowString(stat.Ipv4))
	fmt.Printf("\n%s\n", color.HiWhiteString("Trace HTTP Latency"))
	err = t.Execute(os.Stdout, stat)
	if err != nil {
		return err
	}

	reqDirective := &Request{}
	if len(resp.Request.Header.Values("host")) > 0 {
		reqDirective.hostField = resp.Request.Header.Values("host")[0] // [optional]
	}
	reqDirective.rangeField = resp.Request.Header.Values("range")[0] // [required]

	res := &Response{}
	res.respStatus = resp.Status

	fmt.Printf("%s\n", color.HiWhiteString("Request Headers"))
	fmt.Printf("%s\t\t%s\n", color.HiBlackString("Host"), reqDirective.getHost())
	fmt.Printf("%s\t\t%s\n\n", color.HiBlackString("Range"), reqDirective.getRange())

	fmt.Printf("%s\n", color.HiWhiteString("Response Headers"))
	if res.getRespStatus()[0:1] == "5" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiRedString(res.getRespStatus()))
	} else if res.getRespStatus()[0:1] == "4" {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiYellowString(res.getRespStatus()))
	} else {
		fmt.Printf("%s\t\t%s\n", color.HiBlackString("Status"), color.HiGreenString(res.getRespStatus()))
	}

	for directive, value := range resp.Header {
		length := len(directive)

		if length > 14 {
			word := stringFormat(directive)
			fmt.Printf("%s\t%s\n", color.HiBlackString(word), value[0])
		} else if length < 8 {
			fmt.Printf("%s\t\t%s\n", color.HiBlackString(directive), value[0])
		} else {
			fmt.Printf("%s\t%s\n", color.HiBlackString(directive), value[0])
		}
	}

	fmt.Println()

	return nil

}

func stringFormat(word string) string {

	var prefixBucket []string
	words := strings.Split(word, "-")
	for i, w := range words {
		if i != len(words)-1 {
			prefixBucket = append(prefixBucket, w[:1])
		}
	}
	front := strings.Join(prefixBucket, "")
	wordFormat := strings.Join([]string{front, words[len(words)-1]}, "-")

	if len(wordFormat) > 14 {
		stringFormat(wordFormat)
	}
	return wordFormat
}
