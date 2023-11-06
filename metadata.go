package nessplus

import (
	"strconv"
	"time"
)

type Metadata struct {
	ScanStart time.Time
	ScanEnd   time.Time
}

func extractMetadata(raw NessusRaw) Metadata {
	var meta Metadata

	for _, policy := range raw.Policy.Preferences.ServerPreferences.Preference {
		switch policy.Name.Text {
		case "scan_end_timestamp":
			i, err := strconv.ParseInt(policy.Text, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.ScanEnd = tm

		case "scan_start_timestamp":
			i, err := strconv.ParseInt(policy.Text, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.ScanStart = tm
		}
	}

	return meta
}
