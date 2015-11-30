package main

import (
	"flag"
	"fmt"
	"github.com/srenatus/threatspec-go/threatspec"
	"io/ioutil"
	"os"
)

func main() {
	project := flag.String("project", "default", "project name")
	outFile := flag.String("out", "threatspec.json", "output file")
	flag.Parse()

	ts := threatspec.New(*project)
	if err := ts.Parse(flag.Args()); err != nil {
		fmt.Println("Could not parse flags")
		fmt.Println(err)
		os.Exit(1)
	}

	if err := ts.Validate(); err != nil {
		fmt.Println("WARNING: JSON validation failed")
		fmt.Println(err)
	}

	if err := ioutil.WriteFile(*outFile, []byte(ts.ToJson()), 0644); err != nil {
		fmt.Println("Error writing file")
		fmt.Println(err)
		os.Exit(3)
	}

	fmt.Printf("ThreatSpec written to %s\n", *outFile)
	os.Exit(0)
}
