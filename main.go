package main

import (
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-resty/resty/v2"
	"golang.org/x/net/proxy"
)

func main() {
	// cmd.Execute("1.0")
	/*

	   uri, _ := url.Parse("http://username:password@host:port")
	   # 2 create new transport, base on proxy url
	   client.SetTransport(&http.Transport{
	   	Proxy: http.ProxyURL(uri),
	   })
	   # 3 resty client set proxy
	   client.SetProxy("http://username:password@host:port")
	*/
	client := resty.New()
	client.SetHeader("Range", "bytes=0-1")
	// client.SetProxy("https://vod.ghu.ac.kr:443")

	dialer, err := proxy.SOCKS5("tcp", "110.45.216.205", nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Unable to obtain proxy dialer: %v\n", err)
	}

	ptranport := &http.Transport{
		Dial: dialer.Dial,
	}

	client.SetTransport(ptranport)

	// dialer := &net.Dialer{
	// 	Timeout:   30 * time.Second,
	// 	KeepAlive: 30 * time.Second,
	// }
	// http.DefaultTransport.(*http.Transport).DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
	// 	if addr == "vod.ghu.ac.kr:443" {
	// 		addr = "110.45.216.205:443"
	// 	}
	// 	return dialer.DialContext(ctx, network, addr)
	// }

	uri, _ := url.Parse("http://https://vod.ghu.ac.kr:443@110.45.216.205:443")
	client.SetTransport(&http.Transport{
		Proxy: http.ProxyURL(uri),
	})

	resp, err := client.R().Get("https://vod.ghu.ac.kr/test/test.mp4")

	fmt.Println("Error: ", err)
	fmt.Println("Status Code:", resp.StatusCode())
	fmt.Println("Status:", resp.Status())
	fmt.Println("Body:", resp)

	ti := resp.Request.TraceInfo()
	fmt.Println("TLSHandshake:", ti.TLSHandshake)
	client.RemoveProxy()

}
