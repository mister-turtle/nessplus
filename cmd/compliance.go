package main

import (
	"log"
	"os"
	"path/filepath"

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

	complianceHosts := 0
	for _, host := range overview.Hosts {
		if host.Compliance.Total != 0 {
			complianceHosts++
		}
	}

	log.Printf("Total hosts: %s (%s with compliance runs)\n\n", blue(len(overview.Hosts)), blue(complianceHosts))

	for _, host := range overview.Hosts {

		if host.Compliance.Total == 0 {
			log.Printf("%s (%s) - %s\n", host.Name, host.IP, blue("no compliance results"))
			continue
		}

		log.Printf("%s (%s) - %s/%s/%s/%s/%s\n",
			host.Name,
			host.IP,
			blue(host.Compliance.Total),
			green(host.Compliance.Passed),
			red(host.Compliance.Failed),
			yellow(host.Compliance.Warning),
			blue(host.Compliance.Other))

		for k, v := range host.Compliance.Audits {
			log.Printf("\t%s - %s/%s/%s/%s/%s\n",
				k,
				blue(v.Total),
				green(v.Passed),
				red(v.Failed),
				yellow(v.Warning),
				blue(v.Other),
			)
		}

	}

	log.Printf(argCSVFile)
	/*
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
					err = writer.Write([]string{control.ID, control.Name, control.Status})
					if err != nil {
						return err
					}
				}
				writer.Flush()
			}
		}
	*/
	return nil
}
