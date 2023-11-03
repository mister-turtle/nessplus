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
```sh
NAME:
   nessplus - A new cli application

USAGE:
   nessplus [global options] command [command options] [arguments...]

COMMANDS:
   compliance, c  Parse compliance benchmarks from .nessus files
   help, h        Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h  show help
```

## Todo
- [ ] Scan overview
- [ ] Tidy up compliance CSV code
- [ ] Output host list
- [ ] Output host and ports list
- [ ] Inlcuding CVEs
- [ ] Use searchsploit to find known exploit code
- [ ] Collate issues for reporting (opinionated)