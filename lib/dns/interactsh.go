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
	"github.com/thinkeridea/go-extend/exstrings"
	"poc-go/lib/log"
	"strings"
	"time"
)

const defaultMaxInteractionsCount = 5000
const defaultInteractionDuration = 30 * time.Second
const defaultWatchDuration = 10 * time.Second
const defaultWatchDeleteDuration = 60 * time.Second

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
	configure = configure.MaxSize(defaultMaxInteractionsCount)
	cache := ccache.New(configure)
	i := &Interactsh{
		serverUrl:    "interact.sh",
		client:       c,
		requestCache: cache,
		state:        state,
		pollDuration: 10 * time.Second,
		tickerWatch:  time.NewTicker(defaultWatchDuration),
		tickerDelete: time.NewTicker(defaultWatchDeleteDuration),
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
	check := make(chan bool)
	//fmt.Println("AddRequestCache", substr)
	i.requestCache.Set(substr, check, defaultInteractionDuration)
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
		c := item.Value().(chan bool)
		if !i.IsClosed(c) {
			close(c)
		}
		//fmt.Println("delete", substr)
		i.requestCache.Delete(substr)
	}
}

func (i *Interactsh) ResetCache(key string) {
	index := strings.Index(key, i.serverUrl)
	substr := exstrings.SubString(key, 0, index-1)
	item := i.requestCache.Get(substr)
	if item != nil {
		item.Extend(defaultInteractionDuration)
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
		c := item.Value().(chan bool)
		if !i.IsClosed(c) {
			close(c)
		}
		return true
	}
	return false
}

func (i *Interactsh) forMatches(key string, item *ccache.Item) bool {
	//fmt.Println("forMatches", key, item.Value(), item.Expired())
	if item.Expired() {
		//fmt.Println("is Expired", key)
		c := item.Value().(chan bool)
		if !i.IsClosed(c) {
			c <- false
		}
	}
	return true
}

func (i *Interactsh) IsClosed(ch <-chan bool) bool {
	select {
	case <-ch:
		return true
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
			if !i.IsClosed(item.Value().(chan bool)) {
				item.Value().(chan bool) <- true
			}
		}
	case "http":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			if !i.IsClosed(item.Value().(chan bool)) {
				item.Value().(chan bool) <- true
			}
		}
	case "smtp":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			if !i.IsClosed(item.Value().(chan bool)) {
				item.Value().(chan bool) <- true
			}
		}
	case "responder", "smb":
		item := i.requestCache.Get(interaction.FullId)
		//fmt.Println("checkPoll", item, interaction.FullId)
		if item != nil {
			if !i.IsClosed(item.Value().(chan bool)) {
				item.Value().(chan bool) <- true
			}
		}
	}
}

func (i *Interactsh) Close() {
	i.tickerWatch.Stop()
	i.tickerDelete.Stop()
	i.requestCache.DeleteFunc(func(key string, item *ccache.Item) bool {
		c := item.Value().(chan bool)
		if !i.IsClosed(c) {
			close(c)
		}
		return true
	})
	i.requestCache.Clear()
	_ = i.client.Close()
}
