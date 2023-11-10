# NessPlus
  
This is an on-going project to make Nessus output more useful in day to day pentesting.

## Features
### Compliance
Produce an overview of a Nessus compliance scan: 
* Supports multiple compliance benchmarks per host in a single run
* Optionally write a CSV per host and benchmark containing results
* Optionally print failed controls to the terminal

### Issues
Print out an overview of issues per host
* Sorted by severity rating
* Color highlighted for severity
* Filter on minimum severity level

### Services
Display a list of discovered services per host
* Includes TLS status

## Installation
```sh
go install github.com/mister-turtle/nessplus/cmd/nessplus@latest
```

## Usage
```
                           _            
                          | |          
 _ __   ___  ___ ___ _ __ | |_   _ ___ 
| '_ \ / _ \/ __/ __| '_ \| | | | / __|
| | | |  __/\__ \__ \ |_) | | |_| \__ \
|_| |_|\___||___/___/ .__/|_|\__,_|___/
                    | |                
                    |_|                

NAME:
   nessplus - Parse .nessus files in useful ways

USAGE:
   nessplus [global options] command [command options] [arguments...]

COMMANDS:
   compliance, com Parse compliance benchmarks from .nessus file
   summary, sum    Print out a summary of a nessus scan
   services, serv  Print out discovered services
   help, h         Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## Todo
- [ ] Extract CVEs attached to a host/service
- [ ] Use searchsploit to find known exploit code
- [ ] Collate issues for reporting (opinionated)