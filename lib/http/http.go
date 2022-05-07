package http

import (
	"bytes"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/r0ckysec/go-security/bin/misc"
	"github.com/r0ckysec/go-security/fasthttp"
	"github.com/r0ckysec/go-security/secio"
	"github.com/valyala/fasthttp"
	"gopoc/lib/args"
	"gopoc/lib/proto"
	"io/ioutil"
	http2 "net/http"
	"net/url"
	"strings"
)

func NewRequest(option args.Args, headers cmap.ConcurrentMap, redirect bool) *http.Request {
	request := http.NewRequest()
	request.SetTimeout(option.Timeout)
	request.SetProxy(option.Proxy)
	for tuple := range headers.IterBuffered() {
		request.SetHeaders(tuple.Key, tuple.Val.(string))
	}
	if redirect {
		request.SetRedirects(5)
	}
	// 关闭url自动编码
	request.DisablePathNormalizing(true)
	return request
}

func DoRequest(req *http.Request, method string, url string, data string) (*proto.Response, string, string, error) {
	response, headers, reqRaw, respRaw, err := req.HTTPRaw(method, url, data)
	if headers != nil {
		defer headers.Reset()
	}
	if err != nil {
		return nil, "", "", err
	}
	resp, err := ParseResponse(url, response, headers)
	if err != nil {
		return nil, "", "", err
	}
	return resp, reqRaw, respRaw, err
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

func ParseRequest(oReq *http2.Request) (*proto.Request, error) {
	req := &proto.Request{}
	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)
	header := make(map[string]string)
	for k := range oReq.Header {
		header[k] = strings.Join(oReq.Header.Values(k), "; ")
	}
	req.Headers = header
	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body == nil || oReq.Body == http2.NoBody {
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

func ParseResponse(Url string, body []byte, headers *fasthttp.ResponseHeader) (*proto.Response, error) {
	resp := &proto.Response{}
	header := make(map[string]string)
	resp.Status = int32(headers.StatusCode())
	resp.StatusMsg = misc.Bytes2Str(headers.StatusMessage())
	resp.Proto = misc.Bytes2Str(headers.Protocol())
	parse, err := url.Parse(Url)
	if err != nil {
		return nil, err
	}
	resp.Url = ParseUrl(parse)
	for _, k := range http.GetHeaderKeys(headers) {
		header[k] = misc.Bytes2Str(headers.Peek(k))
	}
	resp.Headers = header
	resp.ContentType = misc.Bytes2Str(headers.ContentType())
	resp.ContentLength = int32(headers.ContentLength())
	resp.Body = body
	return resp, nil
}
