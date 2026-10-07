package shadowquic

import (
	"sync"
	"time"
)

type pipeDeadline struct {
	mu      sync.Mutex
	timer   *time.Timer
	channel chan struct{}
}

func newPipeDeadline() pipeDeadline           { return pipeDeadline{channel: make(chan struct{})} }
func (d *pipeDeadline) Wait() <-chan struct{} { d.mu.Lock(); defer d.mu.Unlock(); return d.channel }
func (d *pipeDeadline) Set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	old := d.channel
	d.channel = make(chan struct{})
	if old != nil {
		select {
		case <-old:
		default:
			close(old)
		}
	}
	if t.IsZero() {
		return
	}
	c := d.channel
	duration := time.Until(t)
	if duration <= 0 {
		close(c)
		return
	}
	d.timer = time.AfterFunc(duration, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.channel == c {
			close(c)
		}
	})
}
