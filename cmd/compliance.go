package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mister-turtle/nessplus"
	"github.com/urfave/cli/v2"
)

func compliance(ctx *cli.Context) error {

	var options = nessplus.ComplianceOptions{
		File:    ctx.String("file"),
		CSVFile: ctx.String("csv"),
	}

	overview, err := nessplus.ParseCompliance(options)
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
			err = writer.Write([]string{"ComplianceID", "Name", "Status"})
			if err != nil {
				return err
			}

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
