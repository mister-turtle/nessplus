package nessplus

import (
	"strconv"
	"time"
)

type Metadata struct {
	PolicyName  string
	Name        string
	RunBy       string
	Description string
	Timing      Timing
}

type Timing struct {
	Start     time.Time
	End       time.Time
	Dueration time.Duration
}

func extractMetadata(raw NessusRaw) Metadata {
	var meta Metadata

	meta.PolicyName = raw.Policy.PolicyName.Text

	for _, policy := range raw.Policy.Preferences.ServerPreferences.Preference {
		switch policy.Name.Text {
		case "scan_end_timestamp":
			i, err := strconv.ParseInt(policy.Value.Text, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.Timing.End = tm

		case "scan_start_timestamp":
			i, err := strconv.ParseInt(policy.Value.Text, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.Timing.Start = tm

		case "scan_name":
			meta.Name = policy.Value.Text
		case "whoami":
			meta.RunBy = policy.Value.Text
		case "description":
			meta.Description = policy.Value.Text
		}

		if !meta.Timing.Start.IsZero() && !meta.Timing.End.IsZero() {
			meta.Timing.Dueration = meta.Timing.End.Sub(meta.Timing.Start)
		}
	}

	return meta
}
