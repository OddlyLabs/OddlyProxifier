package engine

import (
	"sort"
	"sync"
	"time"
)

const (
	trafficSeconds = 300 // length of the rate history
	usageKeys      = 400 // most keys kept per usage table
)

// TrafficPoint is the traffic of one second.
type TrafficPoint struct {
	Time int64 `json:"t"` // unix seconds
	Up   int64 `json:"up"`
	Down int64 `json:"down"`
}

// Usage is what one application, route or rule has transferred so far.
type Usage struct {
	Name   string `json:"name"`
	Conns  int64  `json:"conns"`
	Active int64  `json:"active"`
	Up     int64  `json:"up"`
	Down   int64  `json:"down"`
}

// Traffic is the answer to "where did the bytes go".
type Traffic struct {
	Points []TrafficPoint `json:"points"` // oldest first, one per second
	Apps   []Usage        `json:"apps"`
	Routes []Usage        `json:"routes"`
	Rules  []Usage        `json:"rules"`
}

type usageTable map[string]*Usage

func (t usageTable) get(name string) *Usage {
	u := t[name]
	if u == nil {
		if len(t) >= usageKeys {
			name = "(other)"
			if u = t[name]; u != nil {
				return u
			}
		}
		u = &Usage{Name: name}
		t[name] = u
	}
	return u
}

// list returns a copy, busiest first.
func (t usageTable) list() []Usage {
	out := make([]Usage, 0, len(t))
	for _, u := range t {
		out = append(out, *u)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i].Up+out[i].Down, out[j].Up+out[j].Down
		if a != b {
			return a > b
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// traffic collects the rate history and the per-key totals.
type traffic struct {
	mu     sync.Mutex
	points []TrafficPoint
	lastUp int64
	lastDn int64
	apps   usageTable
	routes usageTable
	rules  usageTable
	stop   chan struct{}
}

func (t *traffic) init() {
	t.apps, t.routes, t.rules = usageTable{}, usageTable{}, usageTable{}
}

// routeName is the key of a connection in the per-route table.
func routeName(ci ConnInfo) string {
	switch {
	case ci.Via != "":
		return ci.Via
	case ci.Action == "block":
		return "(blocked)"
	case ci.Action == "direct":
		return "(direct)"
	}
	return "(failed)"
}

func appKey(ci ConnInfo) string {
	if ci.App == "" {
		return "(unknown)"
	}
	return ci.App
}

// account adds a finished connection to the totals.
func (t *traffic) account(ci ConnInfo) {
	t.mu.Lock()
	for _, u := range []*Usage{t.apps.get(appKey(ci)), t.routes.get(routeName(ci)), t.rules.get(ci.Rule)} {
		u.Conns++
		u.Up += ci.Up
		u.Down += ci.Down
	}
	t.mu.Unlock()
}

// sample appends one point; up and down are the engine's running totals.
func (t *traffic) sample(now time.Time, up, down int64) {
	t.mu.Lock()
	p := TrafficPoint{Time: now.Unix(), Up: up - t.lastUp, Down: down - t.lastDn}
	t.lastUp, t.lastDn = up, down
	if p.Up < 0 {
		p.Up = 0
	}
	if p.Down < 0 {
		p.Down = 0
	}
	if len(t.points) >= trafficSeconds {
		t.points = append(t.points[:0], t.points[1:]...)
	}
	t.points = append(t.points, p)
	t.mu.Unlock()
}

// startSampler records one point a second until stopSampler. rtMu must be held.
func (e *Engine) startSampler() {
	stop := make(chan struct{})
	e.traffic.mu.Lock()
	e.traffic.stop = stop
	s := e.snapshotStats()
	e.traffic.lastUp, e.traffic.lastDn = s.Up, s.Down
	e.traffic.mu.Unlock()
	go func() {
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-tick.C:
				s := e.snapshotStats()
				e.traffic.sample(now, s.Up, s.Down)
			}
		}
	}()
}

func (e *Engine) stopSampler() {
	e.traffic.mu.Lock()
	if e.traffic.stop != nil {
		close(e.traffic.stop)
		e.traffic.stop = nil
	}
	e.traffic.mu.Unlock()
}

// Traffic returns the rate history and the totals per application, route and
// rule, live connections included.
func (e *Engine) Traffic() Traffic {
	active, _ := e.Connections()
	t := &e.traffic
	t.mu.Lock()
	defer t.mu.Unlock()
	merge := func(base usageTable, key func(ConnInfo) string) []Usage {
		tmp := make(usageTable, len(base)+8)
		for k, u := range base {
			c := *u
			tmp[k] = &c
		}
		for _, ci := range active {
			u := tmp.get(key(ci))
			u.Conns++
			u.Active++
			u.Up += ci.Up
			u.Down += ci.Down
		}
		return tmp.list()
	}
	return Traffic{
		Points: append([]TrafficPoint{}, t.points...),
		Apps:   merge(t.apps, appKey),
		Routes: merge(t.routes, routeName),
		Rules:  merge(t.rules, func(ci ConnInfo) string { return ci.Rule }),
	}
}

// ResetTraffic clears the totals and the history.
func (e *Engine) ResetTraffic() {
	t := &e.traffic
	t.mu.Lock()
	t.points = nil
	t.init()
	t.mu.Unlock()
}
