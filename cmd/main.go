package main

import (
	"log"
	"os"

	"github.com/fatih/color"
	"github.com/mister-turtle/nessplus"
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
				Action:  compliance,
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
					&cli.BoolFlag{
						Name:  "print-failed",
						Usage: "[optional] print failed controls to the terminal",
					},
				},
			},
			{
				Name:    "summary",
				Aliases: []string{"s"},
				Usage:   "Print out a summary of a nessus scan",
				Action:  summary,
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "file",
						Usage:    "load scan from a .nessus `FILE`",
						Required: true,
					},
					&cli.IntFlag{
						Name:        "level",
						Usage:       "minimum severity to print 0 - informational to 4 - critical",
						DefaultText: "2",
					},
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func parse(file string) (*nessplus.NessusRun, error) {

	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}

	return nessplus.Parse(fd)

}
