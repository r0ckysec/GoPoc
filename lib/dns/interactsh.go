/**
 * @Description
 * @Author r0cky
 * @Date 2021/12/22 17:12
 **/
package dns

import (
	"github.com/karlseguin/ccache/v2"
	"github.com/projectdiscovery/interactsh/pkg/client"
	"github.com/projectdiscovery/interactsh/pkg/server"
	"github.com/r0ckysec/go-security/log"
	"github.com/thinkeridea/go-extend/exstrings"
	"gopoc/lib/channel"
	"strings"
	"time"
)

const DefaultMaxInteractionsCount = 5000
const DefaultInteractionDuration = 30 * time.Second
const DefaultWatchDuration = 10 * time.Second
const DefaultWatchDeleteDuration = 60 * time.Second

type Interactsh struct {
	serverUrl    string
	client       *client.Client
	requestCache *ccache.Cache
	pollDuration time.Duration
	tickerWatch  *time.Ticker
	tickerDelete *time.Ticker
	state        bool
}

func NewInteractsh() *Interactsh {
	var state = true
	c, err := client.New(&client.Options{
		ServerURL:         "https://interact.sh",
		PersistentSession: false,
		Token:             "",
	})
	if err != nil || c == nil {
		log.Error(err, "Interact.sh Client is nil.")
		state = false
	}
	configure := ccache.Configure()
	configure = configure.MaxSize(DefaultMaxInteractionsCount).Buckets(64).GetsPerPromote(5).PromoteBuffer(2048)
	cache := ccache.New(configure)
	i := &Interactsh{
		serverUrl:    "interact.sh",
		client:       c,
		requestCache: cache,
		state:        state,
		pollDuration: DefaultWatchDuration,
		tickerWatch:  time.NewTicker(DefaultWatchDuration),
		tickerDelete: time.NewTicker(DefaultWatchDeleteDuration),
	}
	return i
}

func (i *Interactsh) State() bool {
	return i.state
}

func (i *Interactsh) GetDomain() string {
	return i.client.URL()
}

func (i *Interactsh) AddRequestCache(key string) {
	index := strings.Index(key, i.serverUrl)
	substr := exstrings.SubString(key, 0, index-1)
	check := channel.NewChannel()
	//fmt.Println("AddRequestCache", substr)
	i.requestCache.Set(substr, check, DefaultInteractionDuration)
}

func (i *Interactsh) GetRequestCache(key string) *ccache.Item {
	index := strings.Index(key, i.serverUrl)
	substr := exstrings.SubString(key, 0, index-1)
	return i.requestCache.Get(substr)
}

func (i *Interactsh) DeleteCache(key string) {
	index := strings.Index(key, i.serverUrl)
	substr := exstrings.SubString(key, 0, index-1)
	item := i.requestCache.Get(substr)
	if item != nil {
		c := item.Value().(*channel.Channel)
		c.SafeClose()
		//fmt.Println("delete", substr)
		i.requestCache.Delete(substr)
	}
}

func (i *Interactsh) ResetCache(key string) {
	index := strings.Index(key, i.serverUrl)
	substr := exstrings.SubString(key, 0, index-1)
	item := i.requestCache.Get(substr)
	if item != nil {
		item.Extend(DefaultInteractionDuration)
		//fmt.Println("ResetCache", substr, item.Expires())
	}
}

func (i *Interactsh) StartPolling() {
	i.client.StartPolling(i.pollDuration, i.checkPoll)
	i.watchCache()
}

func (i *Interactsh) watchCache() {
	go func() {
		for {
			select {
			case <-i.tickerWatch.C:
				i.requestCache.ForEachFunc(i.forMatches)
			}
		}
	}()
	go func() {
		for {
			select {
			case <-i.tickerDelete.C:
				i.requestCache.DeleteFunc(i.deleteMatches)
			}
		}
	}()
}

func (i *Interactsh) deleteMatches(key string, item *ccache.Item) bool {
	//fmt.Println("deleteMatches", key, item.Value(), item.Expired())
	if item.Expired() {
		//fmt.Println("is Expired", key)
		c := item.Value().(*channel.Channel)
		c.SafeClose()
		return true
	}
	return false
}

func (i *Interactsh) forMatches(key string, item *ccache.Item) bool {
	//fmt.Println("forMatches", key, item.Value(), item.Expired())
	if item.Expired() {
		//fmt.Println("is Expired", key)
		c := item.Value().(*channel.Channel)
		i.send(c.C, false)
		//c <- false
	}
	return true
}

func (i *Interactsh) send(ch chan bool, b bool) {
	defer func() {
		if err := recover(); err != nil {
			// 打印异常，关闭资源，退出此函数
			log.Warning(err)
		}
	}()
	if !i.isChanClose(ch) {
		ch <- b
	}
}

func (i *Interactsh) isChanClose(ch chan bool) bool {
	select {
	case _, received := <-ch:
		return !received
	default:
	}
	return false
}

func (i *Interactsh) checkPoll(interaction *server.Interaction) {
	switch interaction.Protocol {
	case "dns":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			c := item.Value().(*channel.Channel)
			i.send(c.C, true)
		}
	case "http":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			c := item.Value().(*channel.Channel)
			i.send(c.C, true)
		}
	case "smtp":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			c := item.Value().(*channel.Channel)
			i.send(c.C, true)
		}
	case "responder", "smb":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			c := item.Value().(*channel.Channel)
			i.send(c.C, true)
		}
	}
}

func (i *Interactsh) Close() {
	i.tickerWatch.Stop()
	i.tickerDelete.Stop()
	i.requestCache.DeleteFunc(func(key string, item *ccache.Item) bool {
		c := item.Value().(*channel.Channel)
		c.SafeClose()
		return true
	})
	i.requestCache.Clear()
	_ = i.client.Close()
	i.state = false
}

func (i *Interactsh) Show() {
	if i.state {
		log.Blue("Cache最大值: %d 当前存在Cache: %d Dropped: %d", DefaultMaxInteractionsCount, i.requestCache.ItemCount(), i.requestCache.GetDropped())
	}
}
