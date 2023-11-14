package nessplus

import (
	"encoding/xml"
	"io"
)

// NessusRun is an abstracted and collated representation from a raw Nessus file.
// The original raw data is accessible through `Raw`
type NessusRun struct {
	Raw      nessusRaw
	Metadata Metadata
	Hosts    []Host
}

// Host represents an instance of a single Host with information collated from plugins and meta tags where possible.
type Host struct {
	Name            string
	IP              string
	OperatingSystem string
	Compliance      Compliance
	Issues          []Issue
	Services        []Service
}

// Parse takes an io.Reader which should produce a valid Nessus XML file.
// Metadata, Compliance scans, Issues, and Services are enumerated to return a *NessusRun .
func Parse(r io.Reader) (*NessusRun, error) {

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var raw = nessusRaw{}
	err = xml.Unmarshal(data, &raw)
	if err != nil {
		return nil, err
	}

	var run = NessusRun{
		Raw:      raw,
		Metadata: extractMetadata(raw),
	}

	var reportHost Host
	for _, host := range raw.Report.ReportHosts {

		// Basic host metadata from ReportHost
		meta := extractHostMetadata(host)
		reportHost.Name = meta.Name
		reportHost.IP = meta.IP
		reportHost.OperatingSystem = meta.OperatingSystem

		// Extract any compliance results from the ReportHost
		compliance, err := parseCompliance(host)
		if err != nil {
			return nil, err
		}
		reportHost.Compliance = compliance

		// Extract issues
		issues, err := parseIssues(host)
		if err != nil {
			return nil, err
		}
		reportHost.Issues = issues

		// Extract services
		services, err := parseServices(host)
		if err != nil {
			return nil, err
		}
		reportHost.Services = services

		run.Hosts = append(run.Hosts, reportHost)
	}
	return &run, nil
}
