package channel

import "sync"

/**
 * @Description
 * @Author r0cky
 * @Date 2022/2/17 16:33
 */

type Channel struct {
	C    chan bool
	once sync.Once
}

func NewChannel() *Channel {
	return &Channel{C: make(chan bool)}
}

func (mc *Channel) SafeClose() {
	mc.once.Do(func() {
		close(mc.C)
	})
}
