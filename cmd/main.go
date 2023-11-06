package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"
)

var banner = `
                           _            
                          | |          
 _ __   ___  ___ ___ _ __ | |_   _ ___ 
| '_ \ / _ \/ __/ __| '_ \| | | | / __|
| | | |  __/\__ \__ \ |_) | | |_| \__ \
|_| |_|\___||___/___/ .__/|_|\__,_|___/
                    | |                
                    |_|                
`

func main() {

	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	log.Println(banner)

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
					&cli.StringFlag{
						Name:  "csv",
						Usage: "optional CSV file to output",
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
