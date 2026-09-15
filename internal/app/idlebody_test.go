package app

import (
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// queueBody serves queued chunks, then an error (or EOF). It never blocks.
type queueBody struct {
	chunks [][]byte
	err    error
	closed atomic.Int32
}

func (b *queueBody) Read(p []byte) (int, error) {
	if len(b.chunks) == 0 {
		if b.err != nil {
			return 0, b.err
		}
		return 0, io.EOF
	}
	chunk := b.chunks[0]
	n := copy(p, chunk)
	if n < len(chunk) {
		b.chunks[0] = chunk[n:]
	} else {
		b.chunks = b.chunks[1:]
	}
	return n, nil
}

func (b *queueBody) Close() error {
	b.closed.Add(1)
	return nil
}

// blockingBody blocks every Read until Close, then yields its data once.
type blockingBody struct {
	data    []byte
	err     error
	release chan struct{}
	closed  atomic.Int32
}

func newBlockingBody(data []byte, err error) *blockingBody {
	return &blockingBody{data: data, err: err, release: make(chan struct{})}
}

func (b *blockingBody) Read(p []byte) (int, error) {
	<-b.release
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	if b.err != nil {
		return 0, b.err
	}
	return 0, io.EOF
}

func (b *blockingBody) Close() error {
	b.closed.Add(1)
	select {
	case <-b.release:
	default:
		close(b.release)
	}
	return nil
}

func TestIdleBodyReadsChunksAndEOF(t *testing.T) {
	body := &queueBody{chunks: [][]byte{[]byte("one"), []byte("two")}}
	idle := newIdleBody(body, time.Second)
	defer idle.Close()

	buf := make([]byte, 64)
	var got strings.Builder
	for i := 0; i < 3; i++ {
		n, err := idle.Read(buf)
		got.Write(buf[:n])
		if i < 2 {
			if err != nil {
				t.Fatalf("read %d error = %v", i, err)
			}
			continue
		}
		// The third read drains the closed chunk channel into io.EOF.
		if err != io.EOF {
			t.Fatalf("final read error = %v, want io.EOF", err)
		}
	}
	if got.String() != "onetwo" {
		t.Fatalf("read %q, want onetwo", got.String())
	}
}

func TestIdleBodyRetainsPendingRemainder(t *testing.T) {
	body := &queueBody{chunks: [][]byte{[]byte("hello")}}
	idle := newIdleBody(body, time.Second)
	defer idle.Close()

	small := make([]byte, 2)
	n, err := idle.Read(small)
	if err != nil || string(small[:n]) != "he" {
		t.Fatalf("first read = %q, %v; want he", small[:n], err)
	}

	rest := make([]byte, 16)
	n, err = idle.Read(rest)
	if err != nil || string(rest[:n]) != "llo" {
		t.Fatalf("pending read = %q, %v; want llo", rest[:n], err)
	}
}

func TestIdleBodyZeroLengthRead(t *testing.T) {
	body := &queueBody{}
	idle := newIdleBody(body, time.Second)
	defer idle.Close()

	n, err := idle.Read(nil)
	if n != 0 || err != nil {
		t.Fatalf("Read(nil) = %d, %v; want 0, nil", n, err)
	}
}

func TestIdleBodyDisabledWatchdogStillDelivers(t *testing.T) {
	body := &queueBody{chunks: [][]byte{[]byte("data")}}
	idle := newIdleBody(body, 0)
	defer idle.Close()

	if idle.idle != 0 {
		t.Fatalf("idle window = %s, want 0", idle.idle)
	}
	buf := make([]byte, 16)
	n, err := idle.Read(buf)
	if err != nil || string(buf[:n]) != "data" {
		t.Fatalf("read with a disabled watchdog = %q, %v", buf[:n], err)
	}

	// A disabled watchdog must still surface EOF.
	if _, err := idle.Read(buf); err != io.EOF {
		t.Fatalf("second read error = %v, want io.EOF", err)
	}
}

func TestIdleBodyTimeoutClosesAndReports(t *testing.T) {
	body := newBlockingBody(nil, nil)
	idle := newIdleBody(body, 20*time.Millisecond)
	defer idle.Close()

	_, err := idle.Read(make([]byte, 16))
	if !isIdleTimeout(err) {
		t.Fatalf("Read error = %v, want an idle timeout", err)
	}
	if got := err.Error(); got != "upstream response idle timeout" {
		t.Fatalf("idle error text = %q", got)
	}
	// The watchdog tears the upstream connection down when it fires.
	deadline := time.Now().Add(time.Second)
	for body.closed.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("timeout did not close the upstream body")
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Close is idempotent.
	if err := idle.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if err := idle.Close(); err != nil {
		t.Fatalf("third Close = %v", err)
	}
}

func TestIdleBodyPropagatesReadError(t *testing.T) {
	want := errors.New("boom")
	body := &queueBody{err: want}
	idle := newIdleBody(body, time.Second)
	defer idle.Close()

	if _, err := idle.Read(make([]byte, 16)); err != want {
		t.Fatalf("Read error = %v, want %v", err, want)
	}
}

// Close must let the pump goroutine exit even when a chunk is already buffered
// and nobody is reading it.
func TestIdleBodyPumpExitsOnClose(t *testing.T) {
	for _, tc := range []struct {
		name string
		body *queueBody
	}{
		{name: "data", body: &queueBody{chunks: [][]byte{[]byte("chunk")}}},
		{name: "error", body: &queueBody{err: errors.New("read failed")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idle := &idleBody{
				body:   tc.body,
				idle:   time.Second,
				chunks: make(chan readResult, 1),
				done:   make(chan struct{}),
			}
			// Occupy the buffer and close the done channel before pumping, so
			// the send cannot succeed and the done branch is taken.
			idle.chunks <- readResult{data: []byte("occupied")}
			close(idle.done)

			exited := make(chan struct{})
			go func() {
				idle.pump()
				close(exited)
			}()
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("pump did not exit after Close")
			}
		})
	}
}
