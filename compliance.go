package nessplus

import (
	"log"
	"sort"
	"strings"

	"github.com/maruel/natural"
)

type Compliance struct {
	Total    int
	Passed   int
	Warning  int
	Failed   int
	Other    int
	Controls []Control
}

type Control struct {
	CheckID string
	Name    string
	Status  string
}

func ParseCompliance(host ReportHost) (Compliance, error) {

	var results = make(map[string]Control)
	var checkIds []string
	var hostResult Compliance

	for _, item := range host.ReportItems {

		var result Control
		if item.Compliance == "" {
			continue
		}

		name := item.ComplianceCheckName

		nameSplit := strings.Split(name, " ")
		if len(nameSplit) == 0 {
			result.CheckID = "Unknown"
			result.Status = item.ComplianceResult
			result.Name = name
		} else {
			result.CheckID = nameSplit[0]
			result.Name = strings.Join(nameSplit[1:], " ")
			result.Name = strings.ReplaceAll(result.Name, ",", " ")
			result.Status = item.ComplianceResult
		}

		hostResult.Total++
		switch result.Status {
		case "PASSED":
			hostResult.Passed++
		case "FAILED":
			hostResult.Failed++
		case "WARNING":
			hostResult.Warning++
		default:
			log.Printf("DEBUG: %s\n", result.Status)
			hostResult.Other++
		}

		// append to checkIds slice for sorting
		checkIds = append(checkIds, result.CheckID)

		// add to results map for storing
		results[result.CheckID] = result
	}

	// return a sorted slice of compliance results
	var sorted = make([]Control, len(checkIds))
	sort.Sort(natural.StringSlice(checkIds))
	for i := 0; i < len(checkIds); i++ {
		sorted[i] = results[checkIds[i]]
	}

	hostResult.Controls = sorted
	return hostResult, nil
}
