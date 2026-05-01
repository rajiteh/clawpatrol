package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"hash"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

type Event struct {
	Ts         time.Time `json:"ts"`
	Mode       string    `json:"mode"`
	Agent      string    `json:"agent,omitempty"`
	AgentIP    string    `json:"agent_ip,omitempty"`
	Host       string    `json:"host"`
	Method     string    `json:"method,omitempty"`
	Path       string    `json:"path,omitempty"`
	Status     int       `json:"status,omitempty"`
	In         int64     `json:"in,omitempty"`
	Out        int64     `json:"out,omitempty"`
	Ms         int64     `json:"ms"`
	Action     string    `json:"action,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	ReqSha     string    `json:"req_sha,omitempty"`
	ReqSample  string    `json:"req_sample,omitempty"`
	RespSha    string    `json:"resp_sha,omitempty"`
	RespSample string    `json:"resp_sample,omitempty"`
}

type Sink struct {
	ch    chan Event
	file  *os.File
	drops atomic.Uint64
	mu    sync.Mutex
	subs  []chan Event
}

func NewSink(path string, buf int) (*Sink, error) {
	s := &Sink{ch: make(chan Event, buf)}
	if path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, err
		}
		s.file = f
	}
	go s.drain()
	return s, nil
}

func (s *Sink) Emit(e Event) {
	if s == nil {
		return
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	}
	select {
	case s.ch <- e:
	default:
		s.drops.Add(1)
	}
}

func (s *Sink) Drops() uint64 { return s.drops.Load() }

func (s *Sink) drain() {
	enc := json.NewEncoder(s.file)
	for e := range s.ch {
		if s.file != nil {
			_ = enc.Encode(e)
		}
		s.mu.Lock()
		for _, sub := range s.subs {
			select {
			case sub <- e:
			default:
				// slow consumer; drop
			}
		}
		s.mu.Unlock()
	}
}

func (s *Sink) Subscribe() (<-chan Event, func()) {
	if s == nil {
		ch := make(chan Event)
		close(ch)
		return ch, func() {}
	}
	ch := make(chan Event, 64)
	s.mu.Lock()
	s.subs = append(s.subs, ch)
	s.mu.Unlock()
	cancel := func() {
		s.mu.Lock()
		for i, c := range s.subs {
			if c == ch {
				s.subs = append(s.subs[:i], s.subs[i+1:]...)
				break
			}
		}
		s.mu.Unlock()
	}
	return ch, cancel
}

type sampler struct {
	hash hash.Hash
	cap  int
	buf  bytes.Buffer
	n    int64
}

func newSampler(capBytes int) *sampler {
	return &sampler{hash: sha256.New(), cap: capBytes}
}

func (s *sampler) Write(p []byte) (int, error) {
	s.hash.Write(p)
	s.n += int64(len(p))
	if remain := s.cap - s.buf.Len(); remain > 0 {
		take := len(p)
		if take > remain {
			take = remain
		}
		s.buf.Write(p[:take])
	}
	return len(p), nil
}

func (s *sampler) sha() string {
	if s.n == 0 {
		return ""
	}
	return hex.EncodeToString(s.hash.Sum(nil))
}

func (s *sampler) sample() string {
	if s.buf.Len() == 0 {
		return ""
	}
	if isPrintable(s.buf.Bytes()) {
		return s.buf.String()
	}
	return "binary:" + hex.EncodeToString(s.buf.Bytes()[:min(64, s.buf.Len())])
}

func isPrintable(b []byte) bool {
	for _, x := range b {
		if x == 0 || (x < 0x20 && x != '\n' && x != '\r' && x != '\t') {
			return false
		}
	}
	return true
}

type teeReadCloser struct {
	r io.Reader
	c io.Closer
}

func (t teeReadCloser) Read(p []byte) (int, error) { return t.r.Read(p) }
func (t teeReadCloser) Close() error               { return t.c.Close() }

func wrapBodySampler(rc io.ReadCloser, s *sampler) io.ReadCloser {
	if rc == nil {
		return nil
	}
	return teeReadCloser{r: io.TeeReader(rc, s), c: rc}
}
