# NessPlus
  
This is an on-going project to make Nessus output more useful in day to day pentesting.

## Features
**Compliance**  
Produce an overview of a Nessus compliance scan and optionally output a CSV file containing Compliance ID, Name, and Status.

## Installation
```sh
go install github.com/mister-turtle/nessplus@latest
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
   compliance, c  Parse compliance benchmarks from .nessus file
   help, h        Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## Todo
- [X] Metadata extraction
- [X] Tidy up compliance CSV code
- [ ] Extract host list
- [ ] Extract host and port list
- [ ] Extract CVEs attached to a host/service
- [ ] Use searchsploit to find known exploit code
- [ ] Collate issues for reporting (opinionated)