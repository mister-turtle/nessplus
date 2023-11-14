package nessplus

import (
	"fmt"
	"sort"
)

var Severities = []string{
	"Informational",
	"Low",
	"Medium",
	"High",
	"Critical",
}

func getSeverity(level int) string {
	if level >= len(Severities) {
		return fmt.Sprintf("Unknown-%d", level)
	}
	if level < 0 {
		return fmt.Sprintf("Unknown-%d", level)
	}
	return Severities[level]
}

type Issue struct {
	PluginID    string
	Name        string
	Description string
	Severity    string
	SeverityInt int
}

func parseIssues(host reportHost) ([]Issue, error) {

	var issues []Issue

	for _, item := range host.ReportItems {
		issue := Issue{
			PluginID:    item.PluginID,
			Name:        item.PluginName,
			Description: item.Synopsis,
			SeverityInt: item.Severity,
			Severity:    getSeverity(item.Severity),
		}
		issues = append(issues, issue)
	}

	sort.Slice(issues, func(i, j int) bool {
		return issues[i].SeverityInt > issues[j].SeverityInt
	})

	return issues, nil
}
