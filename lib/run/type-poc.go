package run

import (
	"context"
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
	"poc-go/lib/pool"
	"poc-go/lib/proto"
	"poc-go/lib/utils"
	"regexp"
	"sec-tools/bin/misc"
	"strings"
	"sync"
	"time"
)

/**
 * @Description
 * @Author r0cky
 * @Date 2022/2/15 13:59
 */

//10分钟的超时设置
const timeout = time.Minute * 10

type pocwork struct {
	flag struct {
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

func NewWork(scan *PocScan) *pocwork {

	p := &pocwork{}

	p.pool.target = pool.NewPool(scan.threads)
	p.pool.poc = pool.NewPool(scan.threads)

	p.pool.target.Interval = time.Microsecond * 10
	p.pool.poc.Interval = time.Microsecond * 10

	p.watchDog.output = make(chan interface{})
	p.watchDog.wg = &sync.WaitGroup{}
	p.watchDog.trigger = false

	//k.vul = make([]map[string]interface{}, 0, 4096)
	return p
}

func (p *pocwork) TargetFactory(hostArr []string) {
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
		p.flag.Total = len(hostArr)
		p.flag.Unlock()
		for _, host := range hostArr {
			//fmt.Println(host)
			p.pool.target.In <- host
		}
		p.pool.target.InDone()
	}()

	//启动任务调度器
	p.pool.target.Run()
}

func (p *pocwork) PocFactory(pocName string) {
	pocs := core.LoadMultiPoc(pocName)
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
		isVul, err := ExecutePoc(context.Background(), task.Req, task.Poc, task.Resp)
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
		for target := range p.pool.target.Out {
			req := target.(*http.Request)
			for _, poc := range pocs {
				task := Task{
					Req:  req,
					Poc:  poc,
					Resp: cmap.New(),
				}
				p.pool.poc.In <- task
			}
		}
		p.pool.poc.InDone()
	}()

	//启动任务调度器
	p.pool.poc.Run()
}

func (p *pocwork) WatchDog() {

	//触发器校准，每隔60秒会将触发器关闭
	go func() {
		for true {
			time.Sleep(60 * time.Second)
			p.watchDog.trigger = false
			//dns.ReverseHost.Show()
		}
	}()
	//轮询触发器，每隔一段时间会检测触发器是否打开
	go func() {
		for true {
			time.Sleep(59 * time.Second)
			if p.watchDog.trigger == false {
				if num := p.pool.target.JobsList.Length(); num > 0 {
					i := p.pool.target.JobsList.Peek()
					info := i.(string)
					log.Blue("正在进行目标队列梳理，其并发协程数为：%d，队列中协程数为：%d，具体其中的一个协程信息为：%s", num, p.pool.target.JobsList.Length(), info)
					continue
				}
				if num := p.pool.poc.JobsList.Length(); num > 0 {
					i := p.pool.poc.JobsList.Peek()
					info := i.(Task)
					log.Blue("正在进行POC扫描，其并发协程数为：%d，并发进度：[%d/%d]，队列中协程数为：%d，具体其中的一个协程信息为：%s %s", num, p.flag.Current, p.flag.Total, p.pool.poc.JobsList.Length(), info.Req.URL, info.Poc.Name)
					continue
				}
			}
		}
	}()

	p.watchDog.wg.Add(1)
	go func() {
		defer p.watchDog.wg.Done()
		for out := range p.pool.poc.Out {
			p.watchDog.output <- out
		}
	}()

	p.watchDog.wg.Wait()
	close(p.watchDog.output)
}

func (p *pocwork) Output() {
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
			log.IsVul("%s %s", vul.Req.URL, vul.Poc.Name)
			//scan := cmap.New()
			//var reqraw string
			//var resp *proto.Response
			//if request, ok := vul.Resp.Get("request"); ok {
			//	reqraw = request.(string)
			//}
			//if response, ok := vul.Resp.Get("response"); ok {
			//	resp = response.(*proto.Response)
			//} else {
			//	resp = &proto.Response{}
			//}
			//scan.Set("URL", fmt.Sprintf("%s", vul.Req.URL))
			//scan.Set("PocName", vul.Poc.Name)
			//scan.Set("RequestRaw", reqraw)
			//scan.Set("ResponseHeaderRaw", utils.GetProtoRespHeaderRaw(resp))
			//scan.Set("ResponseBody", exbytes.ToString(resp.Body))
			////p.Vuls = append(p.Vuls, scan.Items())
			////if p.chanState {
			////	p.Vul <- scan.Items()
			////}
		}
		//slog.Data(disp)
		//if k.config.Output != nil {
		//	k.config.WriteLine(write)
		//}
	}
}

func ExecutePoc(ctx context.Context, oReq *http.Request, p *core.Poc, resp cmap.ConcurrentMap) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel() //纯粹出于良好习惯，函数退出前调用cancel()
	done := make(chan struct{}, 1)
	res := false
	var err error
	go func() {
		defer func() {
			done <- struct{}{}
		}()
		res, err = executePoc(oReq, p, resp)
	}()
	select {
	case <-done:
	case <-ctx.Done():
		log.WarningF("协程超时退出 %s %s", oReq.URL.String(), p.Name)
	}
	return res, err
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
