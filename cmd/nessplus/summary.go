package main

import (
	"log"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

func summary(ctx *cli.Context) error {

	argFile := ctx.String("file")
	argMinLevel := ctx.Int("level")

	run, err := parse(argFile)
	if err != nil {
		return err
	}

	printMetadata(run.Metadata)

	for _, host := range run.Hosts {
		log.Printf("Host: %s [ip:%s,os:%s]\n", host.Name, host.IP, host.OperatingSystem)
		for _, issue := range host.Issues {
			if issue.SeverityInt >= argMinLevel {
				switch issue.Severity {
				case "Informational":
					color.Green("\t[%s] %s\n", issue.Severity, issue.Name)
				case "Low":
					color.Yellow("\t[%s] %s\n", issue.Severity, issue.Name)
				case "Medium":
					color.HiYellow("\t[%s] %s\n", issue.Severity, issue.Name)
				case "High":
					color.Red("\t[%s] %s\n", issue.Severity, issue.Name)
				case "Critical":
					color.HiRed("\t[%s] %s\n", issue.Severity, issue.Name)
				}

			}
		}
		log.Println()
	}

	return nil
}
