package util

import (
	"sync"
	"time"
)

type Cacher struct {
	lock      chan bool
	ttl       time.Duration
	last      time.Time
	generator func() (interface{}, error)
	data      interface{}
	ready     bool
	cond      *sync.Cond
}

func NewCacher(ttl time.Duration, generator func() (interface{}, error)) *Cacher {
	lock := make(chan bool, 1)
	lock <- true
	return &Cacher{
		lock:      lock,
		ttl:       ttl,
		generator: generator,
		cond:      sync.NewCond(&sync.Mutex{}),
	}
}

func (self *Cacher) Fetch() (interface{}, error) {
	if self.last.Add(self.ttl).Before(time.Now()) {
		select {
		case baton := <-self.lock:
			// Do the thing
			newData, genErr := self.generator()

			if genErr == nil {
				self.data = newData
				self.last = time.Now()
				if !self.ready {
					self.ready = true
					self.cond.Broadcast()
				}
			}
			self.lock <- baton
			return newData, genErr
		default:
		}
	}

	if !self.ready {
		self.cond.L.Lock()
		for !self.ready {
			self.cond.Wait()
		}
		self.cond.L.Unlock()
	}

	return self.data, nil
}
