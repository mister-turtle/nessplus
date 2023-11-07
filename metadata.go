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
	Start    time.Time
	End      time.Time
	Duration time.Duration
}

func extractMetadata(raw NessusRaw) Metadata {
	var meta Metadata

	meta.PolicyName = raw.Policy.PolicyName

	for _, policy := range raw.Policy.Preferences.Server.Preferences {
		switch policy.Name {
		case "scan_end_timestamp":
			i, err := strconv.ParseInt(policy.Value, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.Timing.End = tm

		case "scan_start_timestamp":
			i, err := strconv.ParseInt(policy.Value, 10, 64)
			if err != nil {
				break
			}
			tm := time.Unix(i, 0)
			meta.Timing.Start = tm

		case "scan_name":
			meta.Name = policy.Value
		case "whoami":
			meta.RunBy = policy.Value
		case "description":
			meta.Description = policy.Value
		}

		if !meta.Timing.Start.IsZero() && !meta.Timing.End.IsZero() {
			meta.Timing.Duration = meta.Timing.End.Sub(meta.Timing.Start)
		}
	}

	return meta
}

type HostMetadata struct {
	Name            string
	IP              string
	OperatingSystem string
}

func extractHostMetadata(host ReportHost) HostMetadata {
	var meta HostMetadata

	meta.Name = host.Name

	for _, tag := range host.HostProperties.Tags {
		switch tag.Name {
		case "hostname":
			meta.Name = tag.Data
		case "os":
			meta.OperatingSystem = tag.Data
		case "host-ip":
			meta.IP = tag.Data
		}
	}

	return meta
}
