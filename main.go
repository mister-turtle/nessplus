package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

func main() {

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:    "compliance",
				Aliases: []string{"c"},
				Usage:   "Parse compliance benchmarks from .nessus files",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Usage:    ".nessus file to import",
						Required: true,
					},
				},
				Action: compliance,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
