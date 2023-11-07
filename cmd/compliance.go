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

	argFile := ctx.String("file")
	argCSVFile := ctx.String("csv")

	fd, err := os.Open(argFile)
	if err != nil {
		return err
	}

	overview, err := nessplus.Parse(fd)
	if err != nil {
		return err
	}

	log.Printf("File - %s\n", filepath.Base(argFile))
	log.Println()
	printMetadata(overview.Metadata)

	log.Printf("Total hosts: %d\n", len(overview.Hosts))
	for _, host := range overview.Hosts {
		log.Printf("%s (%s)\n", host.Name, host.IP)
		log.Printf("\tTotal (%d) / Passed (%d) / Failed (%d) / Warning (%d) / Other (%d)\n", host.Compliance.Total, host.Compliance.Passed, host.Compliance.Failed, host.Compliance.Warning, host.Compliance.Other)
	}

	if argCSVFile != "" {

		dir := filepath.Dir(argCSVFile)
		base := filepath.Base(argCSVFile)
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

			for _, control := range host.Compliance.Controls {
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
