package graph

import (
	"context"
	"fmt"
	"testing"

	"github.com/Tmwakalasya/deadcheck/internal/testutil"
)

func BenchmarkNPMGraph(b *testing.B) {
	for _, total := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("packages=%d", total), func(b *testing.B) {
			dir := testutil.NPMProject(b, 50, total)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				result, err := New().Build(context.Background(), dir, Options{})
				if err != nil {
					b.Fatal(err)
				}
				if result.Partial || result.DependencyCount != total {
					b.Fatalf("incorrect graph: count=%d, warnings=%v", result.DependencyCount, result.Warnings)
				}
			}
		})
	}
}

// BenchmarkWhy measures explanation of an already-resolved graph, excluding
// graph construction, process startup, and terminal/JSON rendering.
func BenchmarkWhy(b *testing.B) {
	for _, total := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprintf("packages=%d", total), func(b *testing.B) {
			dir := testutil.NPMProject(b, 50, total)
			result, err := New().Build(context.Background(), dir, Options{})
			if err != nil {
				b.Fatal(err)
			}
			if result.Partial || result.DependencyCount != total {
				b.Fatal("invalid fixture graph")
			}
			opts := ExplainOptions{Query: testutil.PackageName(total - 1), MaxPaths: 10}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				why := Explain(result, opts)
				if why.MatchCount != 1 || len(why.Matches[0].Paths) != 10 || !why.Matches[0].Truncated {
					b.Fatal("unexpected explanation paths")
				}
			}
		})
	}
}
