# NessPlus
  
This is a quick project to take a .nessus scan report and pull out the compliance points, sort them, and print them to CSV.
Currently, this just prints to stdout and can be redirected to a CSV file.

## Installation
```sh
go install github.com/mister-turtle/nessplus@latest
```

## Usage
```sh
Usage of nessplus
  -f string
        Nessus file to import

nessus-compliance-2-csv -f ./CIS-2.0.0-Windows-10-L1.nessus > ./CIS-2.0.0-Windows-10-L1.csv
```

## Todo
- [ ] Scan overview
- [ ] Tidy up compliance CSV code
- [ ] Output host list
- [ ] Output host and ports list
- [ ] Inlcuding CVEs
- [ ] Use searchsploit to find known exploit code
- [ ] Collate issues for reporting (opinionated)