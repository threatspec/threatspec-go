package main

import (
	"flag"
	"fmt"
	"github.com/srenatus/threatspec-go/threatspec"
	"io/ioutil"
)

func main() {
	project := flag.String("project", "default", "project name")
	outFile := flag.String("out", "threatspec.json", "output file")
	flag.Parse()

	ts := threatspec.New(*project)
	if err := ts.Parse(flag.Args()); err != nil {
		fmt.Println(err)
	} else {
		if err := ioutil.WriteFile(*outFile, []byte(ts.ToJson()), 0644); err != nil {
			fmt.Println(err)
		} else {
			fmt.Printf("ThreatSpec written to %s\n", *outFile)
		}
	}

}
