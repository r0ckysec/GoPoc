package run

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/cel-go/cel"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/panjf2000/ants/v2"
	"github.com/r0ckysec/GoPoc/lib/core"
	"github.com/r0ckysec/GoPoc/lib/dns"
	gchttp "github.com/r0ckysec/GoPoc/lib/http"
	"github.com/r0ckysec/GoPoc/lib/pool"
	"github.com/r0ckysec/GoPoc/lib/proto"
	"github.com/r0ckysec/go-security/bin/misc"
	gshttp "github.com/r0ckysec/go-security/fasthttp"
	"github.com/r0ckysec/go-security/log"
	"github.com/thinkeridea/go-extend/exstrings"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

/**
 * @Description
 * @Author r0cky
 * @Date 2022/2/15 13:59
 */

//10分钟的超时设置
const timeout = time.Minute * 10

type PocWork struct {
	config Config
	flag   struct {
		sync.RWMutex
		Current int
		Total   int
	}
	pool struct {
		target *pool.Pool
		poc    *pool.Pool
	}
	watchDog struct {
		output  chan interface{}
		hydra   chan interface{}
		wg      *sync.WaitGroup
		trigger bool
	}
}

type Config struct {
	Target  []string
	PocName string
	Proxy   string
	Threads int
	Timeout time.Duration
	Webhook string
}

type VulRes struct {
	Url           string `json:"url"`
	PocName       string `json:"poc_name"`
	RequestRaw    string `json:"request_raw"`
	ResponseRaw   string `json:"response_raw"`
	ContentLength int32  `json:"content_length"`
	CreateTime    int64  `json:"create_time"`
}

func NewWork(config Config) *PocWork {

	p := &PocWork{
		config: config,
	}

	hostThreads := len(p.config.Target)
	hostThreads = hostThreads/5 + 1
	if hostThreads > 400 {
		hostThreads = 400
	}

	p.pool.target = pool.NewPool(hostThreads)
	p.pool.poc = pool.NewPool(p.config.Threads * 4)

	p.pool.target.Interval = time.Microsecond * 10
	p.pool.poc.Interval = time.Microsecond * 10

	p.watchDog.output = make(chan interface{})
	p.watchDog.wg = &sync.WaitGroup{}
	p.watchDog.trigger = false

	//k.vul = make([]map[string]interface{}, 0, 4096)
	return p
}

func (p *PocWork) TargetFactory() {
	//处理目标方法
	p.pool.target.Function = func(i interface{}) interface{} {
		target := i.(string)
		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			log.Error(err, target)
			return nil
		}
		return req
	}
	//目标列表进入流水线
	go func() {
		p.flag.Lock()
		p.flag.Total = len(p.config.Target)
		p.flag.Unlock()
		for _, host := range p.config.Target {
			//fmt.Println(host)
			p.pool.target.In <- host
		}
		p.pool.target.InDone()
	}()

	//启动任务调度器
	p.pool.target.Run()
}

func (p *PocWork) PocFactory() {
	pocs := core.LoadMultiPoc(p.config.PocName)
	p.flag.Lock()
	p.flag.Total = p.flag.Total * len(pocs)
	p.flag.Unlock()
	//处理目标方法
	p.pool.poc.Function = func(i interface{}) interface{} {
		defer func() {
			p.flag.Lock()
			p.flag.Current++
			p.flag.Unlock()
		}()
		task := i.(Task)
		isVul, err := p.ExecutePoc(context.Background(), task.Req, task.Poc, task.Result)
		if err != nil {
			log.Error(task.Poc.Name, err)
			//os.Exit(0)
			return nil
		}
		if isVul {
			return task
		}
		return nil
	}
	//POC列表进入流水线
	go func() {
		var wg int32 = 0
		var threads = p.config.Threads
		for target := range p.pool.target.Out {
			req := target.(*http.Request)
			atomic.AddInt32(&wg, 1)
			go func() {
				defer func() { atomic.AddInt32(&wg, -1) }()
				for _, poc := range pocs {
					task := Task{
						Req:    req,
						Poc:    poc,
						Result: cmap.New(),
					}
					p.pool.poc.In <- task
				}
			}()
			for int(wg) >= threads {
				time.Sleep(1 * time.Second)
			}
		}
		for wg > 0 {
			time.Sleep(1 * time.Second)
		}
		p.pool.poc.InDone()
	}()

	//启动任务调度器
	p.pool.poc.Run()
}

func (p *PocWork) WatchDog() {
	p.watchDog.wg.Add(1)
	//触发器轮询时间
	waitTime := 30 * time.Second
	//轮询触发器，每隔一段时间会检测触发器是否打开
	go func() {
		for true {
			time.Sleep(waitTime)
			if p.watchDog.trigger == false {
				var b float64
				if p.flag.Total > 0 {
					b = float64(p.flag.Current) / float64(p.flag.Total) * 100
				}
				log.Blue(
					"当前运行情况为:目标主机序列并发 [%d], POC检测并发 [%d], 并发进度：[%d/%d] %s",
					p.pool.target.JobsList.Length(),
					p.pool.poc.JobsList.Length(),
					p.flag.Current, p.flag.Total,
					fmt.Sprintf("%.2f%%", b),
				)
			}
		}
	}()
	time.Sleep(time.Millisecond * 500)
	//触发器校准，每隔一段时间将触发器关闭
	go func() {
		for true {
			time.Sleep(waitTime)
			p.watchDog.trigger = false
		}
	}()
	go func() {
		defer p.watchDog.wg.Done()
		for out := range p.pool.poc.Out {
			p.watchDog.output <- out
		}
	}()
	p.watchDog.wg.Wait()
	close(p.watchDog.output)
}

func (p *PocWork) Output() {
	newPool, err := ants.NewPool(100)
	if err != nil {
		return
	}
	defer newPool.Release()
	request := gshttp.NewRequest()
	// 关闭自动编码
	request.DisablePathNormalizing(true)
	//输出POC命中结果
	for out := range p.watchDog.output {
		if out == nil {
			continue
		}
		//打开触发器,若长时间无输出，触发器会输出进度
		p.watchDog.trigger = true
		//输出结果
		switch out.(type) {
		case Task:
			if out == nil {
				continue
			}
			vul := out.(Task)
			log.Hack("%s %s", vul.Req.URL, vul.Poc.Name)
			if p.config.Webhook != "" {
				v := new(VulRes)
				v.CreateTime = time.Now().UnixNano() / 1e6
				v.Url = vul.Req.URL.String()
				v.PocName = vul.Poc.Name
				if request, ok := vul.Result.Get("request"); ok {
					v.RequestRaw = request.(string)
				}
				if response, ok := vul.Result.Get("response"); ok {
					v.ResponseRaw = response.(string)
				}
				if contentLength, ok := vul.Result.Get("content_length"); ok {
					v.ContentLength = contentLength.(int32)
				}
				bytes, err := json.Marshal(v)
				if err != nil {
					return
				}
				_ = newPool.Submit(func() {
					_, _ = request.Post(p.config.Webhook, misc.Bytes2Str(bytes))
				})
			}
		}
	}
}

func (p *PocWork) ExecutePoc(ctx context.Context, oReq *http.Request, poc *core.Poc, result cmap.ConcurrentMap) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() //纯粹出于良好习惯，函数退出前调用cancel()
	done := make(chan struct{}, 1)
	res := false
	var err error
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		res, err = p.executePoc(oReq, poc, result)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		log.WarningF("协程超时退出 %s %s", oReq.URL.String(), poc.Name)
	}
	return res, err
}

func (p *PocWork) executePoc(oReq *http.Request, poc *core.Poc, result cmap.ConcurrentMap) (bool, error) {
	log.Debug(oReq.URL.String(), poc.Name)
	c := core.NewEnvOption()
	c.UpdateCompileOptions(poc.Set)
	env, err := core.NewEnv(&c)
	if err != nil {
		log.ErrorF("environment creation error: %s\n", err)
		return false, err
	}
	variableMap := cmap.New()
	req, err := gchttp.ParseRequest(oReq)
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

	//优先解析newReverse(), 在进行random函数的解析，payload放最后解析
	for _, setItem := range poc.Set {
		if setItem.Key == nil || setItem.Key == "" {
			continue
		}
		key := setItem.Key.(string)
		value := setItem.Value.(string)
		// 反连平台
		if value == "newReverse()" && !variableMap.Has(key) {
			variableMap.Set(key, p.newReverse())
			continue
		}
		if strings.Contains(strings.ToLower(key), "payload") {
			continue
		}
		if strings.Contains(strings.ToLower(value), "random") && strings.Contains(strings.ToLower(value), "(") && !variableMap.Has(key) {
			out, err := core.Evaluate(env, value, variableMap.Items())
			if err != nil {
				log.Error(err)
				continue
			}
			switch value := out.Value().(type) {
			case *proto.UrlType:
				variableMap.Set(key, core.UrlTypeToString(value))
			case int64:
				variableMap.Set(key, int(value))
			default:
				variableMap.Set(key, fmt.Sprintf("%v", out))
			}
		}
	}

	for _, setItem := range poc.Set {
		if setItem.Key == "" {
			continue
		}
		key := setItem.Key.(string)
		value := setItem.Value.(string)
		//expression := p.Set[k]
		//fmt.Println(key, value)
		//if k != "payload" {
		// 反连平台
		//if value == "newReverse()" {
		//	variableMap.Set(key, p.newReverse())
		//	//get, _ := variableMap.Get(key)
		//	//fmt.Println(get, oReq.URL.String())
		//	continue
		//}
		if strings.Contains(strings.ToLower(key), "payload") {
			continue
		}
		if !variableMap.Has(key) {
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
	}
	//最后解析payload
	for _, setItem := range poc.Set {
		if setItem.Key == "" {
			continue
		}
		key := setItem.Key.(string)
		value := setItem.Value.(string)
		if strings.Contains(strings.ToLower(key), "payload") && !variableMap.Has(key) {
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
	}

	//if p.Set["payload"] != "" {
	//	out, err := Evaluate(env, p.Set["payload"], variableMap)
	//	if err != nil {
	//		return false, err
	//	}
	//	variableMap["payload"] = fmt.Sprintf("%v", out)
	//}

	if poc.Groups != nil {
		return p.doGroups(env, poc.Groups, variableMap, oReq, req, result)
	} else {
		return p.doRules(env, poc.Rules, variableMap, oReq, req, result)
	}

}

func (p *PocWork) doGroups(env *cel.Env, groups map[string][]*core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, result cmap.ConcurrentMap) (bool, error) {
	// groups 就是多个rules 任何一个rules成功 即返回成功
	for id, rules := range groups {
		rulesResult, err := p.doRules(env, rules, variableMap, oReq, req, result)
		if err != nil || !rulesResult {
			continue
		}
		// groups中一个rules成功 即返回成功
		if rulesResult {
			result.Set("ruleId", id)
			return rulesResult, nil
		}
	}
	return false, nil
}

func (p *PocWork) doRules(env *cel.Env, rules []*core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, result cmap.ConcurrentMap) (bool, error) {
	success := false
	for _, rule := range rules {
		pathsResult, err := p.doPaths(env, rule, variableMap, oReq, req, result)
		if err != nil || !pathsResult {
			success = false
			break
		}
		success = true
	}
	return success, nil
}

func (p *PocWork) doPaths(env *cel.Env, rule *core.Rule, variableMap cmap.ConcurrentMap, oReq *http.Request, req *proto.Request, result cmap.ConcurrentMap) (bool, error) {
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
		for _, header := range rule.Headers {
			if header.Key == nil || header.Key == "" {
				continue
			}
			headers.Set(header.Key.(string), header.Value)
		}
		//headers.MSet(misc.ToMap(rule.Headers))
		body := FixBody(rule.Body)
		for tuple := range variableMap.IterBuffered() {
			_, isMap := tuple.Val.(map[string]string)
			if isMap {
				continue
			}
			value := fmt.Sprintf("%v", tuple.Val)
			for t := range headers.IterBuffered() {
				a := exstrings.Replace(fmt.Sprintf("%v", t.Val), "{{"+tuple.Key+"}}", value, -1)
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

		newRequest := gshttp.NewRequest()
		// 关闭自动编码
		newRequest.DisablePathNormalizing(true)
		newRequest.SetTimeout(int(p.config.Timeout.Seconds()))
		newRequest.SetProxy(p.config.Proxy)
		for tuple := range headers.IterBuffered() {
			newRequest.SetHeaders(tuple.Key, tuple.Val.(string))
		}
		if rule.FollowRedirects {
			newRequest.SetRedirects(5)
		}
		//newRequest, err := http.NewRequest(rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), strings.NewReader(body))
		//if err != nil {
		//	log.Error(err)
		//	return false, err
		//}
		//newRequest.Header = oReq.Header.Clone()
		//for tuple := range headers.IterBuffered() {
		//	newRequest.Header.Set(tuple.Key, tuple.Val.(string))
		//}
		resp, reqRaw, respRaw, err := gchttp.DoRequest(newRequest, rule.Method, fmt.Sprintf("%s://%s%s", req.Url.Scheme, req.Url.Host, req.Url.Path), body)
		if err != nil {
			if !strings.Contains(rule.Expression, ".wait(") {
				return false, err
			}
		}
		//if resp == nil {
		//	resp = &proto.Response{}
		//}
		variableMap.Set("response", resp)
		result.Set("request", reqRaw)
		result.Set("response", respRaw)
		if resp != nil {
			result.Set("content_length", resp.ContentLength)
		} else {
			result.Set("content_length", int32(0))
		}
		// 将响应头加入search规则
		//headerRaw := header.String()
		//if header != nil {
		//	header.Reset()
		//}
		// 先判断响应页面是否匹配search规则
		if rule.Search != "" {
			result := p.doSearch(strings.TrimSpace(rule.Search), respRaw)
			if result != nil && len(result) > 0 { // 正则匹配成功
				for k, v := range result {
					variableMap.Set(k, v)
				}
				//return true, nil
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

func (p *PocWork) doSearch(re string, body string) map[string]string {
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
				_, ok := paramsMap[name]
				if i > 0 && i <= len(r) && r[i] != "" && !ok {
					paramsMap[name] = r[i]
				}
			}
		}
		return paramsMap
	}
	return nil
}

func (p *PocWork) newReverse() *proto.Reverse {
	//letters := "1234567890abcdefghijklmnopqrstuvwxyz"
	//randSource := rand.New(rand.NewSource(time.Now().Unix()))
	//sub := utils.RandStr(8)
	dnshost := dns.Server.GetDomain()
	if len(dnshost) <= 9 {
		log.Error("获取 dnshost 失败")
		return nil
	}
	//if global.CeyeDomain == "" {
	//	return &proto.Reverse{}
	//} else {
	//	dnshost = global.CeyeDomain
	//}
	urlStr := fmt.Sprintf("http://%s", dnshost)
	u, _ := url.Parse(urlStr)
	//fmt.Println(u.Hostname())
	if dns.Server.Interactsh.State() {
		dns.Server.Interactsh.AddRequestCache(u.Hostname())
	}
	return &proto.Reverse{
		Url:                gchttp.ParseUrl(u),
		Domain:             u.Hostname(),
		Ip:                 "",
		IsDomainNameServer: false,
	}
}

func FixBody(body string) string {
	body = exstrings.Replace(body, "\r\n", "\n", -1)
	body = exstrings.Replace(body, "\n", "\r\n", -1)
	return body
}
