// Credit for the base of the XML structs goes to Tom Steele / lLair Framework
// https://github.com/lair-framework/go-nessus/blob/master/nessus.go

package nessplus

import (
	"encoding/xml"
	"io"
)

type NessusRaw struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Policy  Policy   `xml:"Policy"`
	Report  Report   `xml:"Report"`
}

type Policy struct {
	PolicyName  string      `xml:",chardata"`
	Preferences Preferences `xml:"Preferences"`
}

type Preferences struct {
	Server ServerPreferences `xml:"ServerPreferences"`
}

type ServerPreferences struct {
	Preferences []Preference `xml:"preference"`
}

type Preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// Report has a name and contains all the host details.
type Report struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []ReportHost `xml:"ReportHost"`
}

// ReportHost containts the hostname or ip address for the host and
// all vulnerability and service information.
type ReportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties HostProperties `xml:"HostProperties"`
	ReportItems    []ReportItem   `xml:"ReportItem"`
}

// HostProperties are tags filled with likely useless information.
type HostProperties struct {
	Tags []Tag `xml:"tag"`
}

// Tag is used to split the tag into name and the tag content.
type Tag struct {
	Name string `xml:"name,attr"`
	Data string `xml:",chardata"`
}

// ReportItem is vulnerability plugin output.
type ReportItem struct {
	Port                       int      `xml:"port,attr"`
	SvcName                    string   `xml:"svc_name,attr"`
	Protocol                   string   `xml:"protocol,attr"`
	Severity                   int      `xml:"severity,attr"`
	PluginID                   string   `xml:"pluginID,attr"`
	PluginName                 string   `xml:"pluginName,attr"`
	PluginFamily               string   `xml:"pluginFamily,attr"`
	PluginType                 string   `xml:"plugin_type"`
	PluginVersion              string   `xml:"plugin_version"`
	Fname                      string   `xml:"fname"`
	RiskFactor                 string   `xml:"risk_factor"`
	Synopsis                   string   `xml:"synopsis"`
	Description                string   `xml:"description"`
	Solution                   string   `xml:"solution"`
	PluginOutput               string   `xml:"plugin_output"`
	SeeAlso                    string   `xml:"see_also"`
	CVE                        []string `xml:"cve"`
	BID                        []string `xml:"bid"`
	XREF                       []string `xml:"xref"`
	PluginModificationDate     string   `xml:"plugin_modification_date"`
	PluginPublicationDate      string   `xml:"plugin_publication_date"`
	VulnPublicationDate        string   `xml:"vuln_publication_date"`
	ExploitabilityEase         string   `xml:"exploitability_ease"`
	ExploitAvailable           bool     `xml:"exploit_available"`
	ExploitFrameworkCanvas     bool     `xml:"exploit_framework_canvas"`
	ExploitFrameworkMetasploit bool     `xml:"exploit_framework_metasploit"`
	ExploitFrameworkCore       bool     `xml:"exploit_framework_core"`
	MetasploitName             string   `xml:"metasploit_name"`
	CanvasPackage              string   `xml:"canvas_package"`
	CoreName                   string   `xml:"core_name"`
	CVSSVector                 string   `xml:"cvss_vector"`
	CVSSBaseScore              float64  `xml:"cvss_base_score"`
	CVSSTemporalScore          string   `xml:"cvss_temporal_score"`
	Compliance                 string   `xml:"compliance"`
	ComplianceResult           string   `xml:"compliance-result"`
	ComplianceActualValue      string   `xml:"compliance-actual-value"`
	ComplianceCheckID          string   `xml:"compliance-check-id"`
	ComplianceAuditFile        string   `xml:"compliance-audit-file"`
	ComplianceCheckName        string   `xml:"compliance-check-name"`
}

type NessusRun struct {
	Raw      NessusRaw
	Metadata Metadata
	Hosts    []Host
}

type Host struct {
	Name            string
	IP              string
	OperatingSystem string
	Compliance      Compliance
}

func Parse(r io.Reader) (*NessusRun, error) {

	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	var raw = NessusRaw{}
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
		compliance, err := ParseCompliance(host)
		if err != nil {
			return nil, err
		}
		reportHost.Compliance = compliance

		run.Hosts = append(run.Hosts, reportHost)
	}
	return &run, nil
}
