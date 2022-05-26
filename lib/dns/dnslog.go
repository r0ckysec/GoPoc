package dns

import (
	"github.com/r0ckysec/GoPoc/lib/utils"
	"github.com/r0ckysec/go-security/bin/misc"
	http "github.com/r0ckysec/go-security/fasthttp"
	"github.com/r0ckysec/go-security/log"
	"github.com/r0ckysec/go-security/random"
	"github.com/thinkeridea/go-extend/exstrings"
	"strings"
	"time"
)

/**
 * @Description
 * @Author r0cky
 * @Date 2022/5/25 16:21
 */

type Dnslog struct {
	serverUrl string
	state     bool
	cookie    string
	domain    string
	req       *http.Request
}

func NewDnslog() *Dnslog {
	var state = true
	req := http.NewRequest()
	body, err := req.Get("http://www.dnslog.cn/")
	if err != nil || len(body) == 0 {
		log.Error(err, "dnslog 请求失败. 请切换其他dnslog平台")
		state = false
	}
	i := &Dnslog{
		serverUrl: "dnslog.cn",
		state:     state,
		req:       http.NewRequest(),
	}
	//i.req.SetProxy("http://127.0.0.1:65432")
	return i
}

func (i *Dnslog) GetDomain() string {
	body, header, err := i.req.GetH("http://www.dnslog.cn/getdomain.php?t=" + random.RandStr(16))
	if err != nil || len(body) != 16 {
		//log.Error(err)
		return ""
	}
	i.cookie = misc.Bytes2Str(header.Peek("Set-Cookie"))
	i.domain = misc.Bytes2Str(body)
	sub := utils.RandStr(8)
	return strings.Join([]string{sub, i.domain}, ".")
}

func (i *Dnslog) getRecords(flag string) bool {
	i.req.SetHeaders("Cookie", i.cookie)
	body, err := i.req.Get("http://www.dnslog.cn/getrecords.php?t=" + random.RandStr(16))
	if err != nil {
		//log.Error(err)
		return false
	}
	if strings.Contains(misc.Bytes2Str(body), flag) {
		return true
	}
	return false
}

func (i *Dnslog) CheckDnslog(domain string) bool {
	index := strings.Index(domain, i.serverUrl)
	substr := exstrings.SubString(domain, 0, index-1)
	watchTicker := time.NewTicker(2 * time.Second)
	watchDeleteTicker := time.NewTicker(10 * time.Second)
	defer watchTicker.Stop()
	defer watchDeleteTicker.Stop()
	for {
		select {
		case <-watchTicker.C:
			if i.getRecords(substr) {
				return true
			}
		case <-watchDeleteTicker.C:
			return false
		}
	}
}
