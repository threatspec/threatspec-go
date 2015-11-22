# ThreatSpec-Go package

For more information on ThreatSpec, see http://threatspec.org

## Warning: experimental status

This version of threatspec-go natively parses Go source files and generates a json file to be used for reports and DFDs.

## Usage

    $ ./threatspec-go --project Simple --out simple.json simple.go
    ThreatSpec written to simple.json
    $ head -5 simple.json
    {
      "boundaries": {
        "@webapp": {
          "name": "WebApp"
        }
