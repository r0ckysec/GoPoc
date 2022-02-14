package utils

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"fmt"
	"github.com/thinkeridea/go-extend/exstrings"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"poc-go/lib/proto"
	"poc-go/lib/utils/chinese"
	"sec-tools/secio"
	"strconv"
	"strings"
	"time"
)

var (
	client           *http.Client
	clientNoRedirect *http.Client
	dialTimout       = 5 * time.Second
	keepAlive        = 15 * time.Second
)
var UserAgents = []string{
	"Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
	"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; AcooBrowser; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0; Acoo Browser; SLCC1; .NET CLR 2.0.50727; Media Center PC 5.0; .NET CLR 3.0.04506)",
	"Mozilla/4.0 (compatible; MSIE 7.0; AOL 9.5; AOLBuild 4337.35; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)",
	"Mozilla/5.0 (Windows; U; MSIE 9.0; Windows NT 9.0; en-US)",
	"Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 2.0.50727; Media Center PC 6.0)",
	"Mozilla/5.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; .NET CLR 1.0.3705; .NET CLR 1.1.4322)",
	"Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.2; .NET CLR 1.1.4322; .NET CLR 2.0.50727; InfoPath.2; .NET CLR 3.0.04506.30)",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN) AppleWebKit/523.15 (KHTML, like Gecko, Safari/419.3) Arora/0.3 (Change: 287 c9dfb30)",
	"Mozilla/5.0 (X11; U; Linux; en-US) AppleWebKit/527+ (KHTML, like Gecko, Safari/419.3) Arora/0.6",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2pre) Gecko/20070215 K-Ninja/2.1.1",
	"Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/20080705 Firefox/3.0 Kapiko/3.0",
	"Mozilla/5.0 (X11; Linux i686; U;) Gecko/20070322 Kazehakase/0.4.5",
	"Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.8) Gecko Fedora/1.9.0.8-1.fc10 Kazehakase/0.5.6",
	"Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/17.0.963.56 Safari/535.11",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/535.20 (KHTML, like Gecko) Chrome/19.0.1036.7 Safari/535.20",
	"Opera/9.80 (Macintosh; Intel Mac OS X 10.6.8; U; fr) Presto/2.9.168 Version/11.52",
}

func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	log.SetOutput(ioutil.Discard)
	dialer := &net.Dialer{
		Timeout:   dialTimout,
		KeepAlive: keepAlive,
	}

	tr := &http.Transport{
		DialContext: dialer.DialContext,
		//MaxConnsPerHost:     0,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     keepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
	}
	if DownProxy != "" {
		u, err := url.Parse(DownProxy)
		if err != nil {
			return err
		}
		tr.Proxy = http.ProxyURL(u)
	}

	client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	clientNoRedirect = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
	}
	clientNoRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return nil
}

func DoRequest(req *http.Request, redirect bool) (*proto.Response, http.Header, error) {
	if req.Body == nil || req.Body == http.NoBody {
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", getUserAgent())
	}

	var oResp *http.Response
	var err error
	var header http.Header
	if redirect {
		oResp, err = client.Do(req)
	} else {
		oResp, err = clientNoRedirect.Do(req)
	}
	if oResp != nil {
		defer oResp.Body.Close()
		header = oResp.Header
	}
	if err != nil {
		return nil, nil, err
	}
	resp, err := ParseResponse(oResp)
	if err != nil {
		return nil, nil, err
	}
	return resp, header, err
}

func ParseUrl(u *url.URL) *proto.UrlType {
	nu := &proto.UrlType{}
	nu.Scheme = u.Scheme
	nu.Domain = u.Hostname()
	nu.Host = u.Host
	nu.Port = u.Port()
	nu.Path = u.EscapedPath()
	nu.Query = u.RawQuery
	nu.Fragment = u.Fragment
	return nu
}

func ParseRequest(oReq *http.Request) (*proto.Request, error) {
	req := &proto.Request{}
	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)
	header := make(map[string]*proto.MapValue)
	for k := range oReq.Header {
		header[k] = new(proto.MapValue)
		header[k].List = oReq.Header.Values(k)
		header[k].Bytes = exstrings.Bytes(strings.Join(header[k].List, "; "))
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http.NoBody {
	} else {
		data, err := secio.ReadAll(oReq.Body)
		if err != nil {
			return nil, err
		}
		req.Body = data
		oReq.Body = ioutil.NopCloser(bytes.NewReader(data))
	}
	return req, nil
}

func ParseResponse(oResp *http.Response) (*proto.Response, error) {
	var resp proto.Response
	header := make(map[string]*proto.MapValue)
	resp.Status = int32(oResp.StatusCode)
	resp.StatusMsg = oResp.Status
	resp.Proto = oResp.Proto
	resp.Url = ParseUrl(oResp.Request.URL)
	for k := range oResp.Header {
		header[k] = new(proto.MapValue)
		header[k].List = oResp.Header.Values(k)
		header[k].Bytes = exstrings.Bytes(strings.Join(header[k].List, "; "))
	}
	resp.Headers = header
	resp.ContentType = oResp.Header.Get("Content-Type")
	resp.Body = GetRespBody(oResp)
	return &resp, nil
}

func GetRespBody(resp *http.Response) []byte {
	if resp != nil {
		defer func() {
			_, _ = io.Copy(ioutil.Discard, resp.Body)
			resp.Body.Close()
			resp.Close = true
		}()
	} else {
		return nil
	}
	body, err := secio.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	utf8Buf := chinese.ByteToUTF8(body)
	return utf8Buf
}

func getRespBody(oResp *http.Response) ([]byte, error) {
	var body []byte
	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, _ := gzip.NewReader(oResp.Body)
		defer gr.Close()
		for {
			buf := make([]byte, 1024)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				//utils.Logger.Error(err)
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
		}
	} else {
		raw, err := secio.ReadAll(oResp.Body)
		if err != nil {
			//utils.Logger.Error(err)
			return nil, err
		}
		//defer oResp.Body.Close()
		body = raw
	}
	return body, nil
}

func Header2String(header http.Header) string {
	result := &strings.Builder{}
	defer result.Reset()
	for i := range header {
		hs := header.Values(i)
		for _, h := range hs {
			result.Write(exstrings.Bytes(fmt.Sprintf("%s: %s\n", i, h)))
		}
	}
	return result.String()
}

func HeaderToMap(header http.Header) map[string][]string {
	var headers = map[string][]string{}
	for i := range header {
		hs := header.Values(i)
		for _, h := range hs {
			headers[i] = append(headers[i], h)
		}
	}
	return headers
}

func GetRespHeaderRaw(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	headerRaw := fmt.Sprintf("%s %s\n", resp.Proto, resp.Status)
	headerRaw += Header2String(resp.Header)
	return headerRaw
}

func GetProtoRespHeaderRaw(resp *proto.Response) string {
	if resp == nil {
		return ""
	}
	result := &strings.Builder{}
	defer result.Reset()
	headerRaw := fmt.Sprintf("%s %s\n", resp.Proto, resp.StatusMsg)
	for k, v := range resp.Headers {
		result.Write(exstrings.Bytes(fmt.Sprintf("%s: %s\n", k, v.String())))
	}
	headerRaw += result.String()
	return headerRaw
}

func GetRequestRaw(req *http.Request) string {
	if req == nil {
		return ""
	}
	raw := &strings.Builder{}
	defer raw.Reset()
	raw.WriteString(fmt.Sprintf("%s %s %s\n", req.Method, req.URL.RequestURI(), req.Proto))
	raw.WriteString(fmt.Sprintf("Host: %s\n", req.Host))
	raw.WriteString(Header2String(req.Header))
	//if req.Method == "POST" {
	//	raw += fmt.Sprintf("Content-Length: %d\n", req.ContentLength)
	//}
	if !req.Close {
		raw.WriteString("Connection: close\n")
	}
	raw.WriteString("\n")
	if req.Body != nil {
		reqBody, _ := req.GetBody()
		defer req.Body.Close() // 必须关闭老的
		body, err := secio.ReadAll(reqBody)
		if err != nil {
			return raw.String()
		}
		req.Body = ioutil.NopCloser(bytes.NewReader(body))
		raw.Write(body)
	}
	return raw.String()
}

func getUserAgent() string {
	rand.Seed(time.Now().UnixNano())
	i := rand.Intn(len(UserAgents))
	return UserAgents[i]
}
