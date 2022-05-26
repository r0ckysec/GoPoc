/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/23 9:17
 **/
package dns

import (
	"fmt"
	"github.com/r0ckysec/GoPoc/lib/utils"
	http "github.com/r0ckysec/go-security/fasthttp"
	"github.com/r0ckysec/go-security/json"
	"github.com/thinkeridea/go-extend/exstrings"
	"strings"
	"time"
)

type Ceye struct {
	serverUrl string
	state     bool
	token     string
	domain    string
	req       *http.Request
}

func NewCeye() *Ceye {
	req := http.NewRequest()
	i := &Ceye{
		serverUrl: "ceye.io",
		state:     true,
		req:       req,
		domain:    "es745b.ceye.io",
		token:     "f93e512782324d79e199f5ffaab227dc",
	}
	//i.req.SetProxy("http://127.0.0.1:65432")
	return i
}

func (i *Ceye) GetDomain() string {
	sub := utils.RandStr(8)
	return strings.Join([]string{sub, i.domain}, ".")
}

func (i *Ceye) getRecords(flag string) bool {
	api := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=dns&filter=%s", i.token, flag)
	body, err := i.req.Get(api)
	if err != nil {
		//log.Error(err)
		return false
	}
	pool := json.JsonPool.Get()
	defer json.JsonPool.Put(pool)
	resp, err := pool.ParseBytes(body)
	if err != nil {
		//log.Error(err)
		return false
	}
	array := resp.GetArray("data")
	if len(array) > 0 {
		return true
	}
	return false
}

func (i *Ceye) CheckDnslog(domain string) bool {
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
