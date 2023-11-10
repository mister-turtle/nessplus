package main

import (
	"fmt"
	"log"

	"github.com/urfave/cli/v2"
)

func services(ctx *cli.Context) error {

	argFile := ctx.String("file")

	run, err := parse(argFile)
	if err != nil {
		return err
	}

	for _, host := range run.Hosts {
		log.Printf("Host: %s\n", host.IP)
		for _, service := range host.Services {
			log.Printf("\t%-9s %-12s [tls:%t]\n", fmt.Sprintf("%s/%d", service.Protocol, service.Port), service.Name, service.TLS)
		}
		log.Println()
	}
	return nil
}
