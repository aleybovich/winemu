package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	fmt.Println("Hello from Go on Windows!", len(os.Args))
	var wg sync.WaitGroup
	results := make([]int, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := 0
			for j := 0; j < 100000; j++ {
				s += j % (i + 1)
			}
			results[i] = s
		}(i)
	}
	wg.Wait()
	fmt.Println("results", results)
	m := map[string]int{}
	for _, w := range strings.Fields("the quick brown fox jumps over the lazy dog the end") {
		m[w]++
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Println(keys, m["the"])
	t := time.Now()
	time.Sleep(10 * time.Millisecond)
	fmt.Println("slept", time.Since(t) >= 10*time.Millisecond)
	wd, _ := os.Getwd()
	fmt.Println("cwd ok", wd != "")
	f, err := os.CreateTemp("", "x")
	if err == nil {
		f.WriteString("data")
		f.Close()
		b, _ := os.ReadFile(f.Name())
		os.Remove(f.Name())
		fmt.Println("tempfile", string(b))
	} else {
		fmt.Println("tempfile err", err)
	}
	defer func() { fmt.Println("recovered:", recover()) }()
	var p *int
	fmt.Println(*p)
}
