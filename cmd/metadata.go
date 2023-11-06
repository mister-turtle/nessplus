package main

import (
	"log"

	"github.com/mister-turtle/nessplus"
)

func printMetadata(meta nessplus.Metadata) {

	log.Printf("Scan Metadata----------\n")
	log.Printf("The scan %s started at %s and ended at %s (%s) by %s\n",
		meta.Name,
		meta.Timing.Start,
		meta.Timing.End,
		meta.Timing.Dueration,
		meta.RunBy,
	)
	log.Printf("")
}
