package lib

import (
	"fmt"
	"github.com/google/cel-go/cel"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/thinkeridea/go-extend/exbytes"
	"github.com/thinkeridea/go-extend/exstrings"
	"net/http"
	"net/url"
	"poc-go/lib/core"
	"poc-go/lib/dns"
	"poc-go/lib/log"
	"poc-go/lib/proto"
	"poc-go/lib/utils"
	"regexp"
	"sec-tools/bin/misc"
	"strings"
	"sync"
	"time"
)

type Task struct {
	Req  *http.Request
	Poc  *core.Poc
	Resp cmap.ConcurrentMap
}

type PocScan struct {
	Vul  chan map[string]interface{}
	Vuls []map[string]interface{}
	//ReverseHost *dns.Interactsh
	proxy     string
	threads   int
	rate      int
	time      time.Duration
	debug     bool
	verbose   bool
	chanState bool
}

var lock = sync.Mutex{}
var current = 0

func NewPocScan() *PocScan {
	return &PocScan{
		Vuls:      make([]map[string]interface{}, 0, 128),
		proxy:     "",
		threads:   10,
		rate:      10 * 10,
		time:      10 * time.Second,
		chanState: false,
	}
}

func (p *PocScan) SetProxy(proxy string) {
	p.proxy = proxy
}

func (p *PocScan) SetThreads(threads int) {
	p.threads = threads
	p.rate = 10 * threads
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

func (p *PocScan) OpenChannel() {
	p.chanState = true
	p.Vul = make(chan map[string]interface{})
}

func (p *PocScan) Show() {
	log.Blue("当前项目进度: %d 已命中漏洞: %d", current, len(p.Vuls))
}

//func (p *PocScan) BatchCheckSinglePoc(targets []string, pocName string, rate int) {
//	if p, err := core.LoadSinglePoc(pocName); err == nil {
//		rateLimit := time.Second / time.Duration(rate)
//		ticker := time.NewTicker(rateLimit)
//		defer ticker.Stop()
//		var tasks []Task
//		for _, target := range targets {
//			req, _ := http.NewRequest("GET", target, nil)
//			task := Task{
//				Req:  req,
//				Poc:  p,
//				Resp: make(map[string]interface{}),
//			}
//			tasks = append(tasks, task)
//		}
//		for result := range checkVul(tasks, ticker) {
//			fmt.Println(result.Req.URL, result.Poc.Name)
//		}
//	}
//}

func (p *PocScan) Scan(targets []string, poc string) {
	log.InitLog(p.debug, p.verbose)
	err := utils.InitHttpClient(p.threads, p.proxy, p.time)
	if err != nil {
		log.Error(err)
	}

	//fmt.Println(path.Ext("poc+/weaver-eoffice-upload-cnvd-2021-49104"))
	p.BatchCheckMultiPoc(targets, poc, p.threads, p.rate)
}

func (p *PocScan) BatchCheckMultiPoc(targets []string, pocName string, threads, rate int) {
	pocs := core.LoadMultiPoc(pocName)
	rateLimit := time.Second / time.Duration(rate)
	ticker := time.NewTicker(rateLimit)
	defer ticker.Stop()
	//if progress.Bar != nil {
	//	progress.Bar.ChangeMax(len(targets) * len(pocs))
	//}

	in := make(chan string)
	go func() {
		for _, target := range targets {
			in <- target
		}
		close(in)
	}()

	worker := func(targets <-chan string, wg *sync.WaitGroup, retCh chan<- []Task) {
		defer wg.Done()
		for target := range targets {
			var tasks []Task
			var results []Task
			req, err := http.NewRequest("GET", target, nil)
			if err != nil {
				log.Error(err, target)
			}
			for _, poc := range pocs {
				task := Task{
					Req:  req,
					Poc:  poc,
					Resp: cmap.New(),
				}
				tasks = append(tasks, task)
			}
			for result := range checkVul(tasks, ticker) {
				results = append(results, result)
			}
			retCh <- results
		}
	}

	do := func() <-chan []Task {
		var wg sync.WaitGroup
		retCh := make(chan []Task, threads)
		for i := 0; i < threads; i++ {
			wg.Add(1)
			go worker(in, &wg, retCh)
		}
		go func() {
			wg.Wait()
			close(retCh)
		}()
		return retCh
	}

	for results := range do() {
		for _, result := range results {
			log.IsVul("%s %s", result.Req.URL, result.Poc.Name)
			scan := cmap.New()
			var reqraw string
			var resp *proto.Response
			if request, ok := result.Resp.Get("request"); ok {
				reqraw = request.(string)
			}
			if response, ok := result.Resp.Get("response"); ok {
				resp = response.(*proto.Response)
			} else {
				resp = &proto.Response{}
			}
			scan.Set("URL", fmt.Sprintf("%s", result.Req.URL))
			scan.Set("PocName", result.Poc.Name)
			scan.Set("RequestRaw", reqraw)
			scan.Set("ResponseHeaderRaw", utils.GetProtoRespHeaderRaw(resp))
			scan.Set("ResponseBody", exbytes.ToString(resp.Body))
			p.Vuls = append(p.Vuls, scan.Items())
			if p.chanState {
				p.Vul <- scan.Items()
			}
		}
	}
	if p.chanState {
		close(p.Vul)
	}
}

//func (p *PocScan) CheckSinglePoc(req *http.Request, pocName string, resp map[string]interface{}) *core.Poc {
//	if p, err := core.LoadSinglePoc(pocName); err == nil {
//		if isVul, err := executePoc(req, p, resp); err == nil {
//			if isVul {
//				return p
//			}
//		}
//	}
//	return nil
//}
//
//func (p *PocScan) CheckMultiPoc(req *http.Request, pocName string, rate int) {
//	rateLimit := time.Second / time.Duration(rate)
//	ticker := time.NewTicker(rateLimit)
//	defer ticker.Stop()
//	var tasks []Task
//	for _, poc := range core.LoadMultiPoc(pocName) {
//		task := Task{
//			Req:  req,
//			Poc:  poc,
//			Resp: make(map[string]interface{}),
//		}
//		tasks = append(tasks, task)
//	}
//	for result := range checkVul(tasks, ticker) {
//		log.Green("%s %s", result.Req.URL, result.Poc.Name)
//	}
//}

func checkVul(tasks []Task, ticker *time.Ticker) <-chan Task {
	var wg sync.WaitGroup
	results := make(chan Task)
	for _, task := range tasks {
		wg.Add(1)
		go func(task Task) {
			defer wg.Done()
			<-ticker.C
			isVul, err := executePoc(task.Req, task.Poc, task.Resp)
			if err != nil {
				log.Error(task.Poc.Name, err)
				//os.Exit(0)
				return
			}
			if isVul {
				results <- task
			}
			lock.Lock()
			current++
			lock.Unlock()
			//if progress.Bar != nil {
			//	_ = progress.Bar.Add(1)
			//}
		}(task)
	}
	go func() {
		wg.Wait()
		close(results)
	}()
	return results
}

func executePoc(oReq *http.Request, p *core.Poc, resp cmap.ConcurrentMap) (bool, error) {
	log.Debug(oReq.URL.String(), p.Name)
	c := core.NewEnvOption()
	c.UpdateCompileOptions(p.Set)
	env, err := core.NewEnv(&c)
	if err != nil {
		log.ErrorF("environment creation error: %s\n", err)
		return false, err
	}
	variableMap := cmap.New()
	req, err := utils.ParseRequest(oReq)
	if err != nil {
		log.Error(err)
		return false, err
	}
	variableMap.Set("request", req)

	// 现在假定set中payload作为最后产出，那么先排序解析其他的自定义变量，更新map[string]interface{}后再来解析payload
	//keys := make([]string, 0)
	//for k := range p.Set {
	//	keys = append(keys, k)
	//}
	//sort.Strings(keys)

	for _, setItem := range p.Set {
		key := setItem.Key.(string)
		value := setItem.Value.(string)
		//expression := p.Set[k]
		//fmt.Println(key, value)
		//if k != "payload" {
		// 反连平台
		if value == "newReverse()" {
			variableMap.Set(key, newReverse())
			//get, _ := variableMap.Get(key)
			//fmt.Println(get, oReq.URL.String())
			continue
		}
		out, err := core.Evaluate(env, value, variableMap.Items())
		if err != nil {
			log.Error(err)
			continue
		}
		switch value := out.Value().(type) {
		// set value 无论是什么类型都先转成string
		case *proto.UrlType:
			variableMap.Set(key, core.UrlTypeToString(value))
		case int64:
			variableMap.Set(key, int(value))
		default:
			variableMap.Set(key, fmt.Sprintf("%v", out))
		}
		//}
	}

	//if p.Set["payload"] != "" {
	//	out, err := Evaluate(env, p.Set["payload"], variableMap)
	//	if err != nil {
	//		return false, err
	//	}
	//	variableMap["payload"] = fmt.Sprintf("%v", out)
	//}

	if p.Groups != nil {
		return doGroups(env, p.Groups, variableMap, oReq, req, resp)
	} else {
		return doRules(env, p.Rules, variableMap, oReq, req, resp)
	}

}

func doGroups(env *cel.Env, groups map[string][]*core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, resp cmap.ConcurrentMap) (bool, error) {
	// groups 就是多个rules 任何一个rules成功 即返回成功
	for _, rules := range groups {
		rulesResult, err := doRules(env, rules, variableMap, oReq, req, resp)
		if err != nil || !rulesResult {
			continue
		}
		// groups中一个rules成功 即返回成功
		if rulesResult {
			return rulesResult, nil
		}
	}
	return false, nil
}

func doRules(env *cel.Env, rules []*core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, resp cmap.ConcurrentMap) (bool, error) {
	success := false
	for _, rule := range rules {
		pathsResult, err := doPaths(env, rule, variableMap, oReq, req, resp)
		if err != nil || !pathsResult {
			success = false
			break
		}
		success = true
	}
	return success, nil
}

func doPaths(env *cel.Env, rule *core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, resultResp cmap.ConcurrentMap) (bool, error) {
	// paths 就是多个path 任何一个path成功 即返回成功
	success := false
	var paths []string
	if rule.Paths != nil {
		paths = rule.Paths
	} else {
		paths = append(paths, rule.Path)
	}
	for _, path := range paths {
		//if i > 0 {
		//	fmt.Println(variableMap["dnshost"])
		//	if reverse, ok := variableMap["dnshost"].(*proto.Reverse); ok {
		//		dns.ReverseHost.ResetCache(reverse.Domain)
		//	}
		//}
		headers := cmap.New()
		headers.MSet(misc.ToMap(rule.Headers))
		body := rule.Body
		for tuple := range variableMap.IterBuffered() {
			_, isMap := tuple.Val.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", tuple.Val)
			for t := range headers.IterBuffered() {
				a := exstrings.Replace(t.Val.(string), "{{"+tuple.Key+"}}", value, -1)
				headers.Set(t.Key, a)
			}

			//for k, v := range headers {
			//	headers[k] = exstrings.Replace(v, "{{"+tuple.Key+"}}", value, -1)
			//	//rule.SafeHeaders.Set(iter.Key, exstrings.Replace(iter.Val.(string), "{{"+tuple.Key+"}}", value, -1))
			//}
			path = exstrings.Replace(strings.TrimSpace(path), "{{"+tuple.Key+"}}", value, -1)
			body = exstrings.Replace(strings.TrimSpace(body), "{{"+tuple.Key+"}}", value, -1)
		}

		if oReq.URL.Path != "" && oReq.URL.Path != "/" {
			req.Url.Path = fmt.Sprint(oReq.URL.Path, path)
		} else {
			req.Url.Path = path
		}
		// 某些poc没有区分path和query，需要处理
		req.Url.Path = exstrings.Replace(req.Url.Path, " ", "%20", -1)
		req.Url.Path = exstrings.Replace(req.Url.Path, "+", "%20", -1)

		newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(body))
		if err != nil {
			log.Error(err)
			return false, err
		}
		newRequest.Header = oReq.Header.Clone()
		for tuple := range headers.IterBuffered() {
			newRequest.Header.Set(tuple.Key, tuple.Val.(string))
		}
		resp, header, err := utils.DoRequest(newRequest, rule.FollowRedirects)
		if err != nil {
			if !strings.Contains(rule.Expression, ".wait(") {
				return false, err
			}
		}
		if resp == nil {
			resp = &proto.Response{}
		}
		variableMap.Set("response", resp)
		resultResp.Set("response", resp)
		resultResp.Set("request", utils.GetRequestRaw(newRequest))
		// 将响应头加入search规则
		headerRaw := utils.Header2String(header)

		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := doSearch(strings.TrimSpace(rule.Search), headerRaw+exbytes.ToString(resp.Body))
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap.Set(k, v)
				}
				return false, nil
			} else {
				return false, nil
			}
		}

		out, err := core.Evaluate(env, rule.Expression, variableMap.Items())
		if err != nil {
			log.Error(err)
			return false, err
		}
		//fmt.Println(fmt.Sprintf("%v, %s", out, out.Type().TypeName()))
		if fmt.Sprintf("%v", out) == "false" { //如果false不继续执行后续rule
			success = false // 如果最后一步执行失败，就算前面成功了最终依旧是失败
			continue
		} else {
			success = true
			break
		}
	}
	return success, nil
}

func doSearch(re string, body string) map[string]string {
	r, err := regexp.Compile(re)
	if err != nil {
		log.Error(err)
		return nil
	}
	result := r.FindAllStringSubmatch(body, -1)
	names := r.SubexpNames()
	if len(result) > 0 && len(names) > 0 {
		paramsMap := make(map[string]string)
		for _, r := range result {
			for i, name := range names {
				if i > 0 && i <= len(r) && r[i] != "" {
					paramsMap[name] = r[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

func newReverse() *proto.Reverse {
	//letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	//randSource := rand.New(rand.NewSource(time.Now().Unix()))
	sub := utils.RandStr(8)
	dnshost := dns.ReverseHost.GetDomain()
	//if global.CeyeDomain == "" {
	//	return &proto.Reverse{}
	//} else {
	//	dnshost = global.CeyeDomain
	//}
	urlStr := fmt.Sprintf("http://%s.%s", sub, dnshost)
	u, _ := url.Parse(urlStr)
	dns.ReverseHost.AddRequestCache(u.Hostname())
	return &proto.Reverse{
		Url:                utils.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}
