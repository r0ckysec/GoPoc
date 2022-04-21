package args

import (
	"github.com/r0ckysec/go-security/goflags"
	"os"
)

/**
 * @Description
 * @Author r0cky
 * @Date 2022/4/20 14:57
 */

type Args struct {
	Debug, Verbose            bool
	Threads, Timeout          int
	Target, List, Proxy, Pocs string
	Webhook                   string
}

var Option = Args{}

func FlagParse() {
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription(`GoPoc 基于xray匹配规则的批量poc检测工具 by r0cky from Zionlab`)
	flagSet.BoolVarP(&Option.Debug, "debug", "d", false, "Enable debug mode.")
	flagSet.BoolVarP(&Option.Verbose, "verbose", "v", false, "Enable verbose mode.")
	flagSet.IntVarP(&Option.Threads, "threads", "T", 10, "并发线程数")
	flagSet.IntVarP(&Option.Timeout, "timeout", "tO", 10, "请求超时时间")
	flagSet.StringVarP(&Option.Proxy, "proxy", "P", "", "设置代理")
	flagSet.StringVarP(&Option.Target, "target", "t", "", "单个或的多个目标测试")
	flagSet.StringVarP(&Option.Pocs, "pocs", "p", "pocs", "加载poc路径")
	flagSet.StringVarP(&Option.Webhook, "webhook", "wh", "", "设置Webhook输出地址")
	_ = flagSet.Parse()

	if len(os.Args) < 2 {
		flagSet.CommandLine.Usage()
		os.Exit(0)
	}
}
