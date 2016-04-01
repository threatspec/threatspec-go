package main

import (
	"flag"
	"fmt"
	"github.com/threatspec/threatspec-go/threatspec"
	"os"
)

func main() {
	flag.Parse()
	_, err := threatspec.LoadFiles(flag.Args())
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	os.Exit(0)
}
