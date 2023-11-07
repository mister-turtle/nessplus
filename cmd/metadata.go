package main

import (
	"log"

	"github.com/mister-turtle/nessplus"
)

func printMetadata(meta nessplus.Metadata) {

	log.Printf("The scan %s started on %s and ended at %s (%s) by %s\n",
		blue(meta.Name),
		green(meta.Timing.Start.Format("Monday, 2 January at 15:04:05 2006")),
		green(meta.Timing.End.Format("Monday, 2 January at 15:04:05 2006")),
		blue(meta.Timing.Duration),
		blue(meta.RunBy),
	)
	log.Printf("")
}
