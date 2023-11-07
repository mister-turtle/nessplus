package nessplus

import (
	"sort"
	"strings"

	"github.com/maruel/natural"
)

// Compliance represents the compliance benchmark run against a single host and includes metadata about the compliance status as a whole along.
type Compliance struct {
	Total    int
	Passed   int
	Warning  int
	Failed   int
	Other    int
	Controls []Control
}

// Control stores the result for a single benchmark control.
type Control struct {
	ID     string
	Name   string
	Status string
}

// ParseCompliance takes a ReportHost and produces a Compliance object to represent the benchmark run against the host.
// control IDs are returned in sorted, ascending order.
func parseCompliance(host ReportHost) (Compliance, error) {

	// use a map to store unsorted compliance controls from the nessus data and maintain a slice of observed IDs to sort later.
	var controls = make(map[string]Control)
	var controlIds []string

	var hostResult Compliance

	for _, item := range host.ReportItems {

		var control Control

		// a report item could be any number of things, filter out non-compliance here
		if item.Compliance == "" {
			continue
		}

		// we want to split "1.1.1.1 control description" into an identifier and a name
		name := item.ComplianceCheckName
		nameSplit := strings.Split(name, " ")

		if len(nameSplit) == 0 {
			control.ID = "Unknown"
			control.Status = item.ComplianceResult
			control.Name = name
		} else {
			control.ID = nameSplit[0]
			control.Name = strings.Join(nameSplit[1:], " ")
			control.Name = strings.ReplaceAll(control.Name, ",", " ")
			control.Status = item.ComplianceResult
		}

		// handle totals
		hostResult.Total++
		switch control.Status {
		case "PASSED":
			hostResult.Passed++
		case "FAILED":
			hostResult.Failed++
		case "WARNING":
			hostResult.Warning++
		default:
			hostResult.Other++
		}

		// append to checkIds slice for sorting
		controlIds = append(controlIds, control.ID)

		// add to results map for storing
		controls[control.ID] = control
	}

	// create a slice to hold the sorted controls then sort the observed control ids slice
	var sorted = make([]Control, len(controlIds))
	sort.Sort(natural.StringSlice(controlIds))

	// iterate through the now sorted id slice and add them from the map into the slice of controls
	for i := 0; i < len(controlIds); i++ {
		sorted[i] = controls[controlIds[i]]
	}

	hostResult.Controls = sorted
	return hostResult, nil
}
