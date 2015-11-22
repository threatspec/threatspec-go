package main

import (
	"flag"
	"fmt"
	"github.com/srenatus/threatspec-go/threatspec"
	"os"
)

func main() {
	flag.Parse()
	ts, err := threatspec.Load(flag.Args())
	if err != nil {
		fmt.Println(err)
		os.Exit(2)
	}
	exposuresFound := false

	for projectName, _ := range ts.Projects {
		if len(ts.Projects[projectName].Exposures) > 0 {
			exposuresFound = true
			for _, exposures := range ts.Projects[projectName].Exposures {
				for _, exposure := range exposures {
					fmt.Printf("WARNING: %s:%s exposed to %s by %s in %s:%s (%d)\n",
						ts.Boundaries[exposure.Boundary].Name,
						ts.Components[exposure.Component].Name,
						ts.Threats[exposure.Threat].Name,
						exposure.Exposure,
						exposure.Source.File,
						exposure.Source.Function,
						exposure.Source.Line)
				}
			}
		}
	}

	if exposuresFound {
		os.Exit(1)
	} else {
		fmt.Println("OK")
		os.Exit(0)
	}
}
