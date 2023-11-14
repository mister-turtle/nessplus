// Credit for the base of the XML structs goes to Tom Steele / Lair Framework
// these have been expanded upon with missing elements and restructured to be easier to work with.
// https://github.com/lair-framework/go-nessus/blob/master/nessus.go
//
// This file contains the raw Nessus XML format used for parsing a Nessus export.
package nessplus

import "encoding/xml"

// nessusRaw is the top level container for parsed data from a raw nessus file.
type nessusRaw struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Policy  policy   `xml:"Policy"`
	Report  report   `xml:"Report"`
}

type policy struct {
	PolicyName  string      `xml:",chardata"`
	Preferences preferences `xml:"Preferences"`
}

type preferences struct {
	Server serverPreferences `xml:"ServerPreferences"`
}

type serverPreferences struct {
	Preferences []preference `xml:"preference"`
}

type preference struct {
	Name  string `xml:"name"`
	Value string `xml:"value"`
}

// Report has a name and contains all the host details.
type report struct {
	Name        string       `xml:"name,attr"`
	ReportHosts []reportHost `xml:"ReportHost"`
}

// ReportHost contains the hostname or ip address for the host and
// all vulnerability and service information.
type reportHost struct {
	Name           string         `xml:"name,attr"`
	HostProperties hostProperties `xml:"HostProperties"`
	ReportItems    []reportItem   `xml:"ReportItem"`
}

// HostProperties are tags filled with likely useless information.
type hostProperties struct {
	Tags []tag `xml:"tag"`
}

// Tag is used to split the tag into name and the tag content.
type tag struct {
	Name string `xml:"name,attr"`
	Data string `xml:",chardata"`
}

// ReportItem is vulnerability plugin output.
type reportItem struct {
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
	ComplianceInfo             string   `xml:"compliance-info"`
	ComplianceSolution         string   `xml:"compliance-solution"`
}
