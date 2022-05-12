package run

import (
	cmap "github.com/orcaman/concurrent-map"
	"github.com/r0ckysec/GoPoc/lib/core"
	"github.com/r0ckysec/go-security/log"
	"net/http"
	"time"
)

/**
 * @Description
 * @Author r0cky
 * @Date 2022/2/15 13:50
 */

type Task struct {
	Req    *http.Request
	Poc    *core.Poc
	Result cmap.ConcurrentMap
}

type PocScan struct {
	//Vul  chan map[string]interface{}
	//Vuls []map[string]interface{}
	//ReverseHost *dns.Interactsh
	proxy   string
	threads int
	time    time.Duration
	debug   bool
	verbose bool
	webhook string
	//chanState bool
}

func NewPocScan() *PocScan {
	return &PocScan{
		//Vuls:      make([]map[string]interface{}, 0, 1024),
		proxy:   "",
		threads: 10,
		time:    10 * time.Second,
		//chanState: false,
	}
}

func (p *PocScan) SetProxy(proxy string) {
	p.proxy = proxy
}

func (p *PocScan) SetThreads(threads int) {
	p.threads = threads
}

func (p *PocScan) SetTime(t time.Duration) {
	p.time = t
}

func (p *PocScan) SetDebug(b bool) {
	p.debug = b
}

func (p *PocScan) SetVerbose(b bool) {
	p.verbose = b
}

func (p *PocScan) SetWebhook(wh string) {
	p.webhook = wh
}

//func (p *PocScan) OpenChannel() {
//	p.chanState = true
//	p.Vul = make(chan map[string]interface{})
//}

func (p *PocScan) Scan(targets []string, poc string) {
	if p.debug {
		log.SetDebug()
	} else if p.verbose {
		log.SetVerbose()
	}
	//err := utils.InitHttpClient(p.threads, p.proxy, p.time)
	//if err != nil {
	//	log.Error(err)
	//}

	config := Config{
		Target:  targets,
		PocName: poc,
		Proxy:   p.proxy,
		Threads: p.threads,
		Timeout: p.time,
		Webhook: p.webhook,
	}
	work := NewWork(config)

	//STEP0: 扫描结果调度器
	time.Sleep(time.Microsecond * 200)
	go work.WatchDog()

	//STEP1: 目标调度器
	time.Sleep(time.Microsecond * 200)
	go work.TargetFactory()

	//STEP2: POC调度器
	time.Sleep(time.Microsecond * 200)
	go work.PocFactory()

	//STEP3: 输出
	work.Output()
}
