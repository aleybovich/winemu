//go:build darwin || linux

package win

import (
	"context"
	"sync/atomic"
)

// Host name-service queries (DNS) can take seconds, so they run on their own
// goroutine while the calling guest thread is parked with sockWait; other
// guest threads keep running. The parked API call is re-executed when the
// query finishes and then collects the result.

type lookupJob struct {
	key  string
	done atomic.Bool
	val  any // written by the goroutine before done is set
	err  error
}

// asyncLookup returns query's result for key. On the first call it starts
// query and parks the thread; ok=false means the caller must return at once
// (the call is re-executed later and its return value is ignored).
// The goroutine ends by itself after at most resolverTimeout.
func asyncLookup[T any](e *Emu, key string, query func(context.Context) (T, error)) (v T, err error, ok bool) {
	n := e.netSt()
	t := e.Cur
	if j := n.lookups[t]; j != nil && j.key == key {
		if !j.done.Load() {
			e.sockWait(j.done.Load, infinite)
			return v, nil, false
		}
		delete(n.lookups, t)
		e.resumeWait()
		if j.val != nil {
			v = j.val.(T)
		}
		return v, j.err, true
	}
	j := &lookupJob{key: key}
	if n.lookups == nil {
		n.lookups = map[*Thread]*lookupJob{}
	}
	n.lookups[t] = j
	k := e.k
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), resolverTimeout)
		defer cancel()
		r, err := query(ctx)
		j.val, j.err = r, err
		j.done.Store(true)
		k.notify() // wake the idle scheduler polling the parked thread
	}()
	e.sockWait(j.done.Load, infinite)
	return v, nil, false
}
