/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/21 18:45
 **/
package main

import (
	"fmt"
	"github.com/thinkeridea/go-extend/exstrings"
	"net/http"
	"os"
	"path"
	"poc-go/lib"
	"poc-go/lib/core"
	"poc-go/lib/dns"
	"poc-go/lib/log"
	"sec-tools/bin/misc"
	"sec-tools/goflags"
	"strings"
	"time"
)
import _ "net/http/pprof"

type args struct {
	Debug, Verbose            bool
	Threads, Timeout          int
	Target, List, Proxy, Pocs string
}

var Args = args{}

func flagParse() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`PocScan 基于xray匹配规则的批量poc检测工具 by r0cky from Zionlab`)
	flagSet.BoolVarP(&Args.Debug, "debug", "d", false, "Enable debug mode.")
	flagSet.BoolVarP(&Args.Verbose, "verbose", "v", false, "Enable verbose mode.")
	flagSet.IntVarP(&Args.Threads, "threads", "T", 10, "并发线程数")
	flagSet.IntVarP(&Args.Timeout, "timeout", "tO", 10, "请求超时时间")
	flagSet.StringVarP(&Args.Proxy, "proxy", "P", "", "设置代理")
	flagSet.StringVarP(&Args.Target, "target", "t", "", "单个或的多个目标测试")
	flagSet.StringVarP(&Args.Pocs, "pocs", "p", "pocs", "加载poc路径")
	_ = flagSet.Parse()

	if len(os.Args) < 2 {
		flagSet.CommandLine.Usage()
		os.Exit(0)
	}
}

func main() {
	go func() {
		fmt.Println(http.ListenAndServe("0.0.0.0:8989", nil))
	}()

	flagParse()
	log.InitLog(Args.Debug, Args.Verbose)
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

	scan := lib.NewPocScan()
	scan.SetProxy(Args.Proxy)
	scan.SetTime(time.Duration(Args.Timeout))
	scan.SetThreads(Args.Threads)
	scan.SetDebug(Args.Debug)
	scan.SetVerbose(Args.Verbose)

	targets := targetParse(Args.Target)
	pocs := pocParse(Args.Pocs)

	//targets := []string{"http://target:8989"} //, "http://target:8080"
	//pocs := "D:\\GoLand\\works\\poc-go\\poc+\\cve-2021-44228-log4j2rce.yml"
	log.Blue("载入目标 %d 个", len(targets))
	log.Blue("载入POC路径 => %s", pocs)
	pocLen := len(core.SelectPoc(pocs))
	log.Blue("载入POC数 %d 个", pocLen)
	log.Green("Scanning ... ")
	//progress.Bar.ChangeMax(len(targets))
	//progress.Bar.Describe("[cyan][Scanning][reset]")
	//_ = progress.Bar.RenderBlank()
	scan.OpenChannel()
	go func() {
		for v := range scan.Vul {
			fmt.Println(v)
		}
	}()
	scan.Scan(targets, pocs)
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

func pocParse(s string) string {
	if strings.HasSuffix(s, ".yml") || strings.HasSuffix(s, ".yaml") {
		return s
	} else {
		return path.Join(s, "*")
	}
}
