package main

import (
	"log"

	"github.com/mister-turtle/nessplus"
)

func printMetadata(meta nessplus.Metadata) {

	log.Printf("The scan %s started on %s and ended at %s (%s) by %s\n",
		meta.Name,
		meta.Timing.Start.Format("Mon Jan 2 15:04:05 MST 2006"),
		meta.Timing.End.Format("Mon Jan 2 15:04:05 MST 2006"),
		meta.Timing.Dueration,
		meta.RunBy,
	)
	log.Printf("")
}
