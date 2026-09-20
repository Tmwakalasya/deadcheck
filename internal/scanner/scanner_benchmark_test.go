package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Tmwakalasya/deadcheck/internal/registry"
	"github.com/Tmwakalasya/deadcheck/internal/testutil"
)

// BenchmarkScan includes disk reads, npm graph resolution, response decoding,
// all health checks, and scoring. Each iteration gets fresh lookup caches.
func BenchmarkScan(b *testing.B) {
	for _, size := range []int{50, 250, 1000} {
		benchmarkScan(b, size, size*10, 10, 0)
	}
	for _, workers := range []int{1, 10, 50} {
		benchmarkScan(b, 100, 1000, workers, 5*time.Millisecond)
	}
	benchmarkScan(b, 1000, 10000, 10, 5*time.Millisecond)
}

func benchmarkScan(b *testing.B, direct, total, workers int, latency time.Duration) {
	name := fmt.Sprintf("direct=%d/locked=%d/workers=%d/latency=%s", direct, total, workers, latency)
	b.Run(name, func(b *testing.B) {
		dir := testutil.NPMProject(b, direct, total)
		metadata := healthyMetadata("1.2.3")
		var requests atomic.Int64
		client := &http.Client{Transport: scanTransport(func(r *http.Request) (*http.Response, error) {
			requests.Add(1)
			if latency > 0 {
				timer := time.NewTimer(latency)
				defer timer.Stop()
				select {
				case <-r.Context().Done():
					return nil, r.Context().Err()
				case <-timer.C:
				}
			}
			body := metadata
			if r.URL.Path == "/v1/query" {
				body = `{"vulns":[]}`
			}
			return &http.Response{StatusCode: 200, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
		})}
		urls := registry.URLs{NPM: "https://fixture.test", OSV: "https://fixture.test"}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			scanner := New(client, urls, Options{Workers: workers})
			result, err := scanner.Scan(context.Background(), dir)
			if err != nil {
				b.Fatal(err)
			}
			if result.Partial || result.CheckedDependencyCount != direct || result.DependencyCount != direct || result.Score == nil || *result.Score != 100 {
				b.Fatalf("benchmark scan incomplete or incorrect: %#v", result)
			}
		}
		b.StopTimer()
		want := int64(b.N) * int64(direct) * 2 // One shared metadata lookup and one OSV lookup per dependency.
		if requests.Load() != want {
			b.Fatalf("expected %d requests, got %d", want, requests.Load())
		}
		b.ReportMetric(float64(requests.Load())/float64(b.N), "requests/op")
	})
}
