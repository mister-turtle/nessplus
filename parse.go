package nessplus

import (
	"encoding/xml"
	"io"
)

type NessusRaw struct {
	XMLName xml.Name `xml:"NessusClientData_v2"`
	Text    string   `xml:",chardata"`
	Policy  struct {
		Text       string `xml:",chardata"`
		PolicyName struct {
			Text string `xml:",chardata"`
		} `xml:"policyName"`
		Preferences struct {
			Text              string `xml:",chardata"`
			ServerPreferences struct {
				Text       string `xml:",chardata"`
				Preference []struct {
					Text string `xml:",chardata"`
					Name struct {
						Text string `xml:",chardata"`
					} `xml:"name"`
					Value struct {
						Text string `xml:",chardata"`
					} `xml:"value"`
				} `xml:"preference"`
			} `xml:"ServerPreferences"`
			PluginsPreferences struct {
				Text string `xml:",chardata"`
				Item []struct {
					Text       string `xml:",chardata"`
					PluginName struct {
						Text string `xml:",chardata"`
					} `xml:"pluginName"`
					PluginId struct {
						Text string `xml:",chardata"`
					} `xml:"pluginId"`
					FullName struct {
						Text string `xml:",chardata"`
					} `xml:"fullName"`
					PreferenceName struct {
						Text string `xml:",chardata"`
					} `xml:"preferenceName"`
					PreferenceType struct {
						Text string `xml:",chardata"`
					} `xml:"preferenceType"`
					PreferenceValues struct {
						Text string `xml:",chardata"`
					} `xml:"preferenceValues"`
					SelectedValue struct {
						Text string `xml:",chardata"`
					} `xml:"selectedValue"`
				} `xml:"item"`
			} `xml:"PluginsPreferences"`
		} `xml:"Preferences"`
		FamilySelection struct {
			Text       string `xml:",chardata"`
			FamilyItem []struct {
				Text       string `xml:",chardata"`
				FamilyName struct {
					Text string `xml:",chardata"`
				} `xml:"FamilyName"`
				Status struct {
					Text string `xml:",chardata"`
				} `xml:"Status"`
			} `xml:"FamilyItem"`
		} `xml:"FamilySelection"`
		IndividualPluginSelection struct {
			Text       string `xml:",chardata"`
			PluginItem []struct {
				Text     string `xml:",chardata"`
				PluginId struct {
					Text string `xml:",chardata"`
				} `xml:"PluginId"`
				PluginName struct {
					Text string `xml:",chardata"`
				} `xml:"PluginName"`
				Family struct {
					Text string `xml:",chardata"`
				} `xml:"Family"`
				Status struct {
					Text string `xml:",chardata"`
				} `xml:"Status"`
			} `xml:"PluginItem"`
		} `xml:"IndividualPluginSelection"`
	} `xml:"Policy"`
	Report struct {
		Text       string `xml:",chardata"`
		Name       string `xml:"name,attr"`
		Cm         string `xml:"cm,attr"`
		ReportHost []struct {
			Text           string `xml:",chardata"`
			Name           string `xml:"name,attr"`
			HostProperties struct {
				Text string `xml:",chardata"`
				Tag  []struct {
					Text string `xml:",chardata"`
					Name string `xml:"name,attr"`
				} `xml:"tag"`
			} `xml:"HostProperties"`
			ReportItem []struct {
				Text           string `xml:",chardata"`
				Port           string `xml:"port,attr"`
				SvcName        string `xml:"svc_name,attr"`
				Protocol       string `xml:"protocol,attr"`
				Severity       string `xml:"severity,attr"`
				PluginID       string `xml:"pluginID,attr"`
				AttrPluginName string `xml:"pluginName,attr"`
				PluginFamily   string `xml:"pluginFamily,attr"`
				Description    struct {
					Text string `xml:",chardata"`
				} `xml:"description"`
				Fname struct {
					Text string `xml:",chardata"`
				} `xml:"fname"`
				PluginModificationDate struct {
					Text string `xml:",chardata"`
				} `xml:"plugin_modification_date"`
				PluginName struct {
					Text string `xml:",chardata"`
				} `xml:"plugin_name"`
				PluginPublicationDate struct {
					Text string `xml:",chardata"`
				} `xml:"plugin_publication_date"`
				PluginType struct {
					Text string `xml:",chardata"`
				} `xml:"plugin_type"`
				RiskFactor struct {
					Text string `xml:",chardata"`
				} `xml:"risk_factor"`
				ScriptVersion struct {
					Text string `xml:",chardata"`
				} `xml:"script_version"`
				Solution struct {
					Text string `xml:",chardata"`
				} `xml:"solution"`
				Synopsis struct {
					Text string `xml:",chardata"`
				} `xml:"synopsis"`
				PluginOutput struct {
					Text string `xml:",chardata"`
				} `xml:"plugin_output"`
				AlwaysRun struct {
					Text string `xml:",chardata"`
				} `xml:"always_run"`
				Iavb struct {
					Text string `xml:",chardata"`
				} `xml:"iavb"`
				Xref struct {
					Text string `xml:",chardata"`
				} `xml:"xref"`
				Agent struct {
					Text string `xml:",chardata"`
				} `xml:"agent"`
				Compliance struct {
					Text string `xml:",chardata"`
				} `xml:"compliance"`
				ComplianceCheckType struct {
					Text string `xml:",chardata"`
				} `xml:"compliance_check_type"`
				ComplianceSupportsParseValidation struct {
					Text string `xml:",chardata"`
				} `xml:"compliance_supports_parse_validation"`
				ComplianceSupportsReplacement struct {
					Text string `xml:",chardata"`
				} `xml:"compliance_supports_replacement"`
				ComplianceBenchmarkVersion struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-benchmark-version"`
				ComplianceCheckName struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-check-name"`
				ComplianceCheckID struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-check-id"`
				ComplianceActualValue struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-actual-value"`
				ComplianceSource struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-source"`
				ComplianceAuditFile struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-audit-file"`
				CompliancePolicyValue struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-policy-value"`
				ComplianceFunctionalID struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-functional-id"`
				ComplianceUname struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-uname"`
				ComplianceInfo struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-info"`
				ComplianceResult struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-result"`
				ComplianceInformationalID struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-informational-id"`
				ComplianceReference struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-reference"`
				ComplianceSolution struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-solution"`
				ComplianceBenchmarkName struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-benchmark-name"`
				ComplianceControlID struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-control-id"`
				ComplianceSeeAlso struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-see-also"`
				ComplianceFullID struct {
					Text string `xml:",chardata"`
				} `xml:"compliance-full-id"`
				ThoroughTests struct {
					Text string `xml:",chardata"`
				} `xml:"thorough_tests"`
				SeeAlso struct {
					Text string `xml:",chardata"`
				} `xml:"see_also"`
			} `xml:"ReportItem"`
		} `xml:"ReportHost"`
	} `xml:"Report"`
}

type NessusRun struct {
	Raw      NessusRaw
	Metadata Metadata
}

func parse(r io.Reader) (*NessusRun, error) {

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
		Raw: raw,
	}

	return &run, nil
}
