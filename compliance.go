package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/maruel/natural"
	"github.com/urfave/cli/v2"
)

type ComplianceOptions struct {
	File    string
	CSVFile string
}

type ComplianceOverview struct {
	Date      string
	HostCount int
	Hosts     []ComplianceHost
}

type ComplianceHost struct {
	Name            string
	IP              string
	OperatingSystem string
	Total           int
	Passed          int
	Warning         int
	Failed          int
	Other           int
	Controls        []ControlResult
	//PercentagePass float
	//PercentageFail float
}

type ControlResult struct {
	CheckID string
	Name    string
	Status  string
}

func compliance(ctx *cli.Context) error {

	var options ComplianceOptions
	options.File = ctx.String("file")
	options.CSVFile = ctx.String("csv")

	overview, err := parseCompliance(ctx, options)
	if err != nil {
		return err
	}

	log.Printf("Overview of %s...\n", filepath.Base(options.File))
	log.Printf("Total hosts: %d\n", len(overview.Hosts))
	for _, host := range overview.Hosts {
		log.Printf("%s (%s)\n", host.Name, host.IP)
		log.Printf("\tTotal (%d) / Passed (%d) / Failed (%d) / Warning (%d) / Other (%d)\n", host.Total, host.Passed, host.Failed, host.Warning, host.Other)
	}

	if options.CSVFile != "" {

		dir := filepath.Dir(options.CSVFile)
		base := filepath.Base(options.CSVFile)
		file := strings.TrimSuffix(base, filepath.Ext(base))

		for _, host := range overview.Hosts {
			csvFileName := filepath.Join(dir, fmt.Sprintf("%s-%s.csv", file, host.Name))
			csvFile, err := os.Create(csvFileName)
			if err != nil {
				return err
			}

			writer := csv.NewWriter(csvFile)
			writer.Write([]string{"ComplianceID", "Name", "Status"})
			for _, control := range host.Controls {
				err = writer.Write([]string{control.CheckID, control.Name, control.Status})
				if err != nil {
					return err
				}
			}
			writer.Flush()
		}
	}

	return nil
}

func parseCompliance(ctx *cli.Context, options ComplianceOptions) (ComplianceOverview, error) {

	fd, err := os.Open(options.File)
	if err != nil {
		log.Fatal(err)
	}

	run, err := Parse(fd)
	if err != nil {
		log.Fatal(err)
	}

	var overview ComplianceOverview
	for _, policy := range run.Policy.Preferences.ServerPreferences.Preference {
		if policy.Name.Text == "scan_end_timestamp" {
			overview.Date = policy.Value.Text
		}
	}

	// a report can contain multiple hosts
	for _, host := range run.Report.ReportHost {

		var results = make(map[string]ControlResult)
		var checkIds []string
		var hostResult ComplianceHost

		hostResult.Name = host.Name

		for _, tag := range host.HostProperties.Tag {
			switch tag.Name {
			case "hostname":
				hostResult.Name = tag.Text
			case "os":
				hostResult.OperatingSystem = tag.Text
			case "host-ip":
				hostResult.IP = tag.Text
			}
		}

		for _, item := range host.ReportItem {

			var result ControlResult
			if item.Compliance.Text == "" {
				continue
			}

			name := item.ComplianceCheckName.Text
			nameSplit := strings.Split(name, " ")
			if len(nameSplit) == 0 {
				result.CheckID = "Unknown"
				result.Status = item.ComplianceResult.Text
				result.Name = name
			} else {
				result.CheckID = nameSplit[0]
				result.Name = strings.Join(nameSplit[1:], " ")
				result.Name = strings.ReplaceAll(result.Name, ",", " ")
				result.Status = item.ComplianceResult.Text
			}

			hostResult.Total++
			switch result.Status {
			case "PASSED":
				hostResult.Passed++
			case "FAILED":
				hostResult.Failed++
			case "WARNING":
				hostResult.Warning++
			default:
				hostResult.Other++
			}

			// append to checkIds slice for sorting
			checkIds = append(checkIds, result.CheckID)

			// add to results map for storing
			results[result.CheckID] = result
		}

		// return a sorted slice of compliance results
		var sorted = make([]ControlResult, len(checkIds))
		sort.Sort(natural.StringSlice(checkIds))
		for i := 0; i < len(checkIds); i++ {
			sorted[i] = results[checkIds[i]]
		}

		hostResult.Controls = sorted
		overview.Hosts = append(overview.Hosts, hostResult)
	}

	return overview, nil
}
