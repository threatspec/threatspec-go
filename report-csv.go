package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"github.com/threatspec/threatspec-go/threatspec"
	"os"
	"strconv"
)

func fatalIfError(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func getBoundaryName(boundary *threatspec.Boundary) string {
	if boundary == nil {
		return ""
	} else {
		return boundary.Name
	}
}

func main() {
	outFile := flag.String("out", "threatspec.csv", "output csv file")

	flag.Parse()

	var err error

	ts, err := threatspec.LoadFiles(flag.Args())
	fatalIfError(err)

	csvFile, err := os.Create(*outFile)
	fatalIfError(err)
	defer csvFile.Close()

	writer := csv.NewWriter(csvFile)

	// CSV header
	writer.Write([]string{
		"boundary",
		"component",
		"threat",
		"type",
		"value",
		"function",
		"file",
		"line",
	})

	for projectName, _ := range ts.Projects {

		for _, ms := range ts.Projects[projectName].Mitigations {
			for _, m := range ms {
				err = writer.Write([]string{
					getBoundaryName(ts.Boundaries[m.Boundary]),
					ts.Components[m.Component].Name,
					ts.Threats[m.Threat].Name,
					"mitigation",
					m.Mitigation,
					m.Source.Function,
					m.Source.File,
					strconv.Itoa(m.Source.Line),
				})
				fatalIfError(err)
			}
		}

		for _, es := range ts.Projects[projectName].Exposures {
			for _, e := range es {
				err = writer.Write([]string{
					getBoundaryName(ts.Boundaries[e.Boundary]),
					ts.Components[e.Component].Name,
					ts.Threats[e.Threat].Name,
					"exposure",
					e.Exposure,
					e.Source.Function,
					e.Source.File,
					strconv.Itoa(e.Source.Line),
				})
				fatalIfError(err)
			}
		}

		for _, trs := range ts.Projects[projectName].Transfers {
			for _, t := range trs {
				err = writer.Write([]string{
					getBoundaryName(ts.Boundaries[t.Boundary]),
					ts.Components[t.Component].Name,
					ts.Threats[t.Threat].Name,
					"transfer",
					t.Transfer,
					t.Source.Function,
					t.Source.File,
					strconv.Itoa(t.Source.Line),
				})
				fatalIfError(err)
			}
		}

		for _, as := range ts.Projects[projectName].Acceptances {
			for _, a := range as {
				err = writer.Write([]string{
					getBoundaryName(ts.Boundaries[a.Boundary]),
					ts.Components[a.Component].Name,
					ts.Threats[a.Threat].Name,
					"acceptance",
					a.Acceptance,
					a.Source.Function,
					a.Source.File,
					strconv.Itoa(a.Source.Line),
				})
				fatalIfError(err)
			}
		}

	}

	fmt.Printf("Writing report to %s\n", *outFile)
	writer.Flush()
	csvFile.Close()
}
