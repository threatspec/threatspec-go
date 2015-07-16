package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/srenatus/threatspec-go/threatspec"
)

var funCovPattern = regexp.MustCompile(`^(?P<loc>[^:]*):(?P<line>[1-9][0-9]+):\s+(?P<fun>[^\s]+)\s+(?P<cov>[0-9]+\.[0-9])%$`)

func parseFunCov(filename string) (map[string]float64, error) {
	ms := make(map[string]float64)
	inFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer inFile.Close()

	scanner := bufio.NewScanner(inFile)
	scanner.Split(bufio.ScanLines)

	for scanner.Scan() {
		line := scanner.Text()
		m := funCovPattern.FindStringSubmatch(line)

		if len(m) > 1 {
			f, _ := strconv.ParseFloat(m[4], 64)
			ms[m[1]+":"+m[2]+":"+m[3]] = f
		}
	}
	return ms, nil
}

func main() {
	var uc []threatspec.Function

	warn := flag.Bool("warn", false, "warn for unmigated exposures [and uncovered mitigations] (default: exit 1)")
	funCovFile := flag.String("func", "", "per function coverage profile to check (default: none)")
	coverageMinStr := flag.String("mincov", "100.0", "minimal converage for mitigation functions (float, default 100.0)")
	flag.Parse()

	coverageMin, err := strconv.ParseFloat(*coverageMinStr, 64)
	if err != nil {
		fmt.Printf("Bad coverage value: %s\n", *coverageMinStr)
		os.Exit(3)
	}

	_, es, ms, _ := threatspec.Files(flag.Args())

	us := threatspec.Unmitigated(es, ms)
	for _, u := range us {
		fmt.Printf("Unmigitated exposure in %s: %s \n", u.Function.LocationString(), u.Name)
	}

	if *funCovFile != "" {
		coverages, err := parseFunCov(*funCovFile)
		if err != nil {
			fmt.Printf("err: %s\n", err)
			os.Exit(2)
		}

		for _, m := range ms {
			fl := m.Function.LocationStartString()
			val, ok := coverages[fl]
			if !ok {
				fmt.Printf("No coverage information for mitigation function %s\n", fl)
			} else {
				if val < coverageMin {
					fmt.Printf("Coverage %.1f < %.1f for mitigation function %s\n", val, coverageMin, fl)
				}
			}
		}
	}

	if !*warn && (len(us) > 0 || len(uc) > 0) {
		os.Exit(1)
	}
}
