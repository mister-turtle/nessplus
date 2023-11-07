package nessplus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/maruel/natural"
)

// Compliance represents the compliance benchmark run against a single host and includes metadata about the compliance status as a whole along.
type Compliance struct {
	Total   int
	Passed  int
	Warning int
	Failed  int
	Other   int
	Audits  map[string]Audit
}

type Audit struct {
	Total    int
	Passed   int
	Warning  int
	Failed   int
	Other    int
	Controls []Control
}

// Control stores the result for a single benchmark control.
type Control struct {
	ID        string
	Name      string
	Status    string
	AuditFile string
}

// ParseCompliance takes a ReportHost and produces a Compliance object to represent the benchmark run against the host.
// control IDs are returned in sorted, ascending order.
func parseCompliance(host ReportHost) (Compliance, error) {

	var unsortedControls = make(map[string]map[string]Control)
	var unsortedControlIds = make(map[string][]string)

	var compliance Compliance
	compliance.Audits = make(map[string]Audit)

	for _, item := range host.ReportItems {

		var control Control

		// a report item could be any number of things, filter out non-compliance here
		if item.Compliance == "" {
			continue
		}

		// nessus can run multiple benchmarks at the same time, grab the audit file used for this control.
		control.AuditFile = item.ComplianceAuditFile

		// create the map of control ID to control in the unsorted map
		if _, ok := unsortedControls[control.AuditFile]; !ok {
			unsortedControls[control.AuditFile] = make(map[string]Control)
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

		// add the control ID into the observed id slice for sorting later
		unsortedControlIds[control.AuditFile] = append(unsortedControlIds[control.AuditFile], control.ID)

		// handle host totals
		auditTotals := compliance.Audits[control.AuditFile]
		compliance.Total++
		auditTotals.Total++

		switch control.Status {
		case "PASSED":
			compliance.Passed++
			auditTotals.Passed++
		case "FAILED":
			compliance.Failed++
			auditTotals.Failed++
		case "WARNING":
			compliance.Warning++
			auditTotals.Warning++
		default:
			compliance.Other++
			auditTotals.Other++
		}

		compliance.Audits[control.AuditFile] = auditTotals
		// handler per-audit totals

		// add to results map for storing
		unsortedControls[control.AuditFile][control.ID] = control
	}

	// for each audit (key) in the map, get the controls map (value)
	for audit, _ := range unsortedControls {

		if ids, ok := unsortedControlIds[audit]; ok {

			var sorted = make([]Control, len(ids))
			sort.Sort(natural.StringSlice(ids))

			for i := 0; i < len(ids); i++ {
				sorted[i] = unsortedControls[audit][ids[i]]
			}
			tmpAudit := compliance.Audits[audit]
			tmpAudit.Controls = sorted
			compliance.Audits[audit] = tmpAudit
		} else {
			return Compliance{}, fmt.Errorf("the control id list %s for sorting does not exist", audit)
		}
	}

	return compliance, nil
}
