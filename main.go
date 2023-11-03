package main

import (
	"flag"
	"log"
	"os"
	"sort"
	"strings"

	"github.com/maruel/natural"
)

func main() {

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	argFile := flag.String("f", "", "Nessus file to import")
	flag.Parse()

	if *argFile == "" {
		flag.Usage()
		os.Exit(1)
	}

	fd, err := os.Open(*argFile)
	if err != nil {
		log.Fatal(err)
	}

	results, err := FromNessusFile(fd)
	if err != nil {
		log.Fatal(err)
	}

	type SimpleResult struct {
		CheckID string
		Name    string
		Status  string
	}

	var simpleResults = make(map[string]SimpleResult)
	var checkIds []string

	for _, item := range results.Report.ReportHost.ReportItem {

		var simple SimpleResult
		if item.Compliance.Text == "" {
			continue
		}
		name := item.ComplianceCheckName.Text
		checkId := strings.Split(name, " ")
		if len(checkId) == 0 {
			log.Printf("ERROR: Could not split compliance name: %s\n", name)
			continue
		}

		simple.CheckID = checkId[0]
		simple.Name = strings.Join(checkId[1:], " ")
		simple.Name = strings.ReplaceAll(simple.Name, ",", " ")
		simple.Status = item.ComplianceResult.Text

		// append to checkIds slice for sorting
		checkIds = append(checkIds, simple.CheckID)

		// add to results map for storing
		simpleResults[simple.CheckID] = simple
	}

	log.Printf("Compliance ID, Name, Result\n")
	sort.Sort(natural.StringSlice(checkIds))
	for _, key := range checkIds {
		log.Printf("%s,%s,%s\n", simpleResults[key].CheckID, simpleResults[key].Name, simpleResults[key].Status)
	}
}
