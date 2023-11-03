# NessPlus
  
This is a quick project to take a .nessus scan report and pull out the compliance points, sort them, and print them to CSV.
Currently, this just prints to stdout and can be redirected to a CSV file.

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