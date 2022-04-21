/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/21 18:45
 **/
package main

import (
	"fmt"
	"github.com/r0ckysec/go-security/bin/misc"
	"github.com/r0ckysec/go-security/log"
	"github.com/thinkeridea/go-extend/exstrings"
	"gopoc/lib/args"
	"gopoc/lib/core"
	"gopoc/lib/dns"
	"gopoc/lib/run"
	"net/http"
	"strings"
	"time"
)
import _ "net/http/pprof"

func main() {
	go func() {
		fmt.Println(http.ListenAndServe("0.0.0.0:8989", nil))
	}()

	args.FlagParse()
	//log.SetDebug()
	//if progress.Bar != nil {
	//	defer progress.Bar.Close()
	//}
	dns.ReverseHost = dns.NewInteractsh()
	if !dns.ReverseHost.State() {
		log.Yellow("reverse host failed!")
		return
	} else {
		defer dns.ReverseHost.Close()
		dns.ReverseHost.StartPolling()
	}

	scan := run.NewPocScan()
	scan.SetProxy(args.Option.Proxy)
	scan.SetTime(time.Duration(args.Option.Timeout) * time.Second)
	scan.SetThreads(args.Option.Threads)
	scan.SetDebug(args.Option.Debug)
	scan.SetVerbose(args.Option.Verbose)
	scan.SetWebhook(args.Option.Webhook)

	targets := targetParse(args.Option.Target)
	//pocs := pocParse(Args.Pocs)

	//targets := []string{"http://target:8989"} //, "http://target:8080"
	//pocs := "D:\\GoLand\\works\\gopoc\\poc+\\cve-2021-44228-log4j2rce.yml"
	log.Blue("载入目标 %d 个", len(targets))
	log.Blue("载入POC路径 => %s", args.Option.Pocs)
	pocLen := len(core.SelectPoc(args.Option.Pocs))
	log.Blue("载入POC数 %d 个", pocLen)
	log.Green("Scanning ... ")
	//var tickerWatch = time.NewTicker(30 * time.Second)
	//defer tickerWatch.Stop()
	//go func() {
	//	for {
	//		select {
	//		case <-tickerWatch.C:
	//			scan.Show()
	//			dns.ReverseHost.Show()
	//		}
	//	}
	//}()
	//progress.Bar.ChangeMax(len(targets))
	//progress.Bar.Describe("[cyan][Scanning][reset]")
	//_ = progress.Bar.RenderBlank()
	//scan.OpenChannel()
	//go func() {
	//	for v := range scan.Vul {
	//		fmt.Println(v)
	//	}
	//}()
	scan.Scan(targets, args.Option.Pocs)
	log.Blue("Scan Done.")
}

func targetParse(str string) []string {
	index := strings.Index(str, "file:")
	if index > -1 {
		subString := exstrings.SubString(str, index+5, 0)
		lineAll := misc.ReadLineAll(subString)
		lineAll = misc.RemoveDuplicatesAndEmpty(lineAll)
		return lineAll
	} else {
		return []string{str}
	}
}

//func pocParse(s string) string {
//	if strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".yaml") {
//		return s
//	} else {
//		return path.Join(s, "*")
//	}
//}
