package main

import (
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
)

var (
	red    = color.New(color.FgRed).SprintFunc()
	blue   = color.New(color.FgBlue).SprintFunc()
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
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
		Name:  "nessplus",
		Usage: "Parse .nessus files in useful ways",
		Commands: []*cli.Command{
			{
				Name:    "compliance",
				Aliases: []string{"c"},
				Usage:   "Parse compliance benchmarks from .nessus file",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Usage:    "load scan from .nessus `FILE`",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "csv",
						Usage: "[optional] CSV `FILE` to output, the hostname will be appended to the filename before the CSV extension",
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
