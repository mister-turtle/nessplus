package nessplus

import (
	"fmt"
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

func parseIssues(host ReportHost) ([]Issue, error) {

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

	return issues, nil
}
