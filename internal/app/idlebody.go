package app

import (
	"io"
	"sync"
	"time"
)

// errUpstreamIdle signals that no upstream bytes arrived within the idle
// window. It is deliberately distinct from context cancellation so a client
// disconnect is never counted as a timeout.
type idleTimeoutError struct{}

func (idleTimeoutError) Error() string { return "upstream response idle timeout" }

func isIdleTimeout(err error) bool {
	_, ok := err.(idleTimeoutError)
	return ok
}

type readResult struct {
	data []byte
	err  error
}

// idleBody wraps an upstream response body with an idle watchdog. A background
// goroutine pumps reads; Read waits for the next chunk or the idle deadline.
// Every delivered chunk resets the window, so a slow-but-steady stream (and
// keepalive comments) never trips it, while a stalled one does.
type idleBody struct {
	body   io.ReadCloser
	idle   time.Duration
	chunks chan readResult
	done   chan struct{}
	once   sync.Once

	mu      sync.Mutex
	pending []byte
}

func newIdleBody(body io.ReadCloser, idle time.Duration) *idleBody {
	ib := &idleBody{
		body:   body,
		idle:   idle,
		chunks: make(chan readResult, 1),
		done:   make(chan struct{}),
	}
	go ib.pump()
	return ib
}

func (b *idleBody) pump() {
	defer close(b.chunks)
	buf := make([]byte, 32*1024)
	for {
		n, err := b.body.Read(buf)
		if n > 0 {
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			select {
			case b.chunks <- readResult{data: chunk}:
			case <-b.done:
				return
			}
		}
		if err != nil {
			select {
			case b.chunks <- readResult{err: err}:
			case <-b.done:
			}
			return
		}
	}
}

func (b *idleBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.pending) > 0 {
		n := copy(p, b.pending)
		b.pending = b.pending[n:]
		return n, nil
	}

	if b.idle <= 0 {
		var never <-chan time.Time // nil channel blocks forever
		return b.deliver(p, never)
	}
	timer := time.NewTimer(b.idle)
	defer timer.Stop()
	return b.deliver(p, timer.C)
}

// deliver consumes the next chunk, or reports a timeout when deadline fires.
// deadline is nil-safe: a nil channel blocks forever.
func (b *idleBody) deliver(p []byte, deadline <-chan time.Time) (int, error) {
	select {
	case res, ok := <-b.chunks:
		if !ok {
			return 0, io.EOF
		}
		if res.err != nil {
			return 0, res.err
		}
		n := copy(p, res.data)
		if n < len(res.data) {
			b.pending = res.data[n:]
		}
		return n, nil
	case <-deadline:
		b.Close()
		return 0, idleTimeoutError{}
	}
}

// Close stops the pump and tears down the upstream connection.
func (b *idleBody) Close() error {
	b.once.Do(func() { close(b.done) })
	return b.body.Close()
}
