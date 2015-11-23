# ThreatSpec-Go package

For more information on ThreatSpec, see http://threatspec.org

## Warning: experimental status

This version of threatspec-go natively parses Go source files and generates a json file to be used for reports and DFDs.

## Building

    $ go build -o threatspec-go main.go


## Usage

Basic usage

    $ threatspec-go --project Simple --out simple.json simple.go
    ThreatSpec written to simple.json

    $ head -5 simple.json
    {
      "boundaries": {
        "@webapp": {
          "name": "WebApp"
        }

Including .threatspec files

    $ cat cwe.threatspec
    alias threat @cwe_319_cleartext_transmission to The software transmits sensitive or security-critical data in cleartext in a communication channel that can be sniffed by unauthorized actors

    $ threatspec-go --project Simple --out simple.json simple.go cwe.threatspec
    ThreatSpec written to simple.json

Including other .json files

    $ cat stride.json
    {
      "threats": {
        "@cats_like_milk": {
          "name": "true story",
          "reference": ""
        }
      }
    }

    $ threatspec-go --project Simple --out simple.json simple.go cwe.threatspec stride.json
    ThreatSpec written to simple.json


