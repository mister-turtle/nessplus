package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/mister-turtle/nessplus"
	"github.com/urfave/cli/v2"
)

func compliance(ctx *cli.Context) error {

	argFile := ctx.String("file")
	argCSVFile := ctx.String("csv")
	argCSVFields := ctx.String("csv-fields")
	argPrintFailed := ctx.Bool("print-failed")

	overview, err := parse(argFile)
	if err != nil {
		return err
	}

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

		for auditName, audit := range host.Compliance.Audits {
			log.Printf("\t%s - %s/%s/%s/%s/%s\n",
				auditName,
				blue(audit.Total),
				green(audit.Passed),
				red(audit.Failed),
				yellow(audit.Warning),
				blue(audit.Other),
			)
			if argPrintFailed {
				for _, control := range audit.Controls {
					if control.Status != "FAILED" {
						continue
					}
					log.Printf("\t\t%s - %s - %s\n",
						control.ID,
						control.Name,
						red(control.Status),
					)
				}
			}
		}

	}

	if argCSVFile != "" {

		dir := filepath.Dir(argCSVFile)
		base := filepath.Base(argCSVFile)
		file := strings.TrimSuffix(base, filepath.Ext(base))

		for _, host := range overview.Hosts {
			for auditName, audit := range host.Compliance.Audits {
				csvFileName := filepath.Join(dir, fmt.Sprintf("%s-%s-%s.csv", file, host.Name, auditName))
				csvFile, err := os.Create(csvFileName)
				if err != nil {
					return err
				}

				writer := csv.NewWriter(csvFile)
				err = writeCSV(writer, audit.Controls, argCSVFields)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func writeCSV(w *csv.Writer, controls []nessplus.Control, argFields string) error {

	if len(controls) == 0 {
		return fmt.Errorf("empty controls set passed to csv writer")
	}

	fields := strings.Split(argFields, ",")
	if len(fields) == 0 {
		return fmt.Errorf("invalid fields passed to csv writer")
	}

	// validate the fields being passed through are actually struct members
	for _, field := range fields {
		_, err := fieldValue(controls[0], field)
		if err != nil {
			return err
		}
	}

	// write the headers
	err := w.Write(fields)
	if err != nil {
		return err
	}

	for _, control := range controls {

		// create the string slice for the CSV writer containing values from
		// the fields
		var printFields []string
		for _, field := range fields {
			val, err := fieldValue(control, field)
			if err != nil {
				return err
			}
			printFields = append(printFields, val)
		}

		// write the values to the CSV
		err = w.Write(printFields)
		if err != nil {
			return err
		}
	}
	w.Flush()
	return nil
}

func fieldValue(control nessplus.Control, field string) (string, error) {

	structType := reflect.TypeOf(control)
	structValues := reflect.ValueOf(control)

	numFields := structType.NumField()

	for i := 0; i < numFields; i++ {
		structField := structType.Field(i)
		if structField.Name == field {
			return fmt.Sprintf("%s", structValues.Field(i)), nil
		}
	}
	return "", fmt.Errorf("field %s was not found", field)
}
