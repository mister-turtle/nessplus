package nessplus

import (
	"sort"
)

type Service struct {
	Port     int
	Protocol string
	Name     string
	TLS      bool
}

func parseServices(host reportHost) ([]Service, error) {

	var services = make(map[int]Service)

	for _, item := range host.ReportItems {

		var service Service

		if item.Port == 0 {
			continue
		}

		service.Port = item.Port
		service.Name = item.SvcName
		service.Protocol = item.Protocol

		switch item.PluginID {
		case "15588", // Web server SSL port detection
			"20007",  // SSL v2 and v3 detection
			"104743", // TLS 1.0 detection
			"121010", // TLS 1.1 detection
			"136318", // TLS 1.2 detection
			"138330": // TLS 1.3 detection
			service.TLS = true
		}

		// update the TLS field from detection plugins. We might need a more
		// thorough merge in the future.
		if existing, ok := services[service.Port]; ok {
			if !existing.TLS {
				existing.TLS = service.TLS
				services[service.Port] = existing
			}
		} else {
			services[service.Port] = service
		}
	}

	var ports []int
	for port := range services {
		ports = append(ports, port)
	}
	sort.Ints(ports)

	var sorted = make([]Service, len(ports))
	for i := 0; i < len(ports); i++ {
		sorted[i] = services[ports[i]]
	}

	return sorted, nil
}
