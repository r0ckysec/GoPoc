/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/22 9:37
 **/
package config

import (
	"github.com/jinzhu/configor"
	"os"
	"path"
	"poc-go/lib/log"
	"sec-tools/bin/misc"
)

var Config = struct {
	Scan struct {
		Threads int    `default:"10"`
		Rate    int    `default:"100"`
		POC     string `default:"pocs/*"`
	}
	Reverse struct {
		ApiKey string `default:""`
		Domain string `default:""`
	}
}{}

func Init() {
	default_config := "config/poc-config.yml"
	if _, err := os.Stat(default_config); os.IsNotExist(err) {
		_ = os.MkdirAll(path.Dir(default_config), os.ModePerm)
		err = misc.WriteLine(default_config, defaultYamlByte)
		if err == nil {
			log.Blue("扫描器初始化成功: %s", default_config)
		} else {
			log.Yellow("扫描器初始化失败！")
		}
	}
	err := configor.Load(&Config, default_config)
	if err != nil {
		log.Yellow("扫描器配置未加载成功！")
	}
	//_ = godotenv.Load()
	//_ = configor.Load(&Config, "config/config.yml")
	//格式化成json输出
	//buf, _ := json.Marshal(Config)
	//fmt.Println(string(buf))
}

var defaultYamlByte = []byte(`# Poc配置
scan:
  threads: 10
  rate: 100
  poc: pocs/*

# 反连平台配置: 目前使用 ceye.io
reverse:
  apikey: ""
  domain: ""
`)
