package threatspec

const ThreatSpecSchemaStrictv0 string = `{
  "schema": "http://json-schema.org/draft-04/schema#",
  "title": "threatspec_schema_strict",
  "type": "object",
  "required": ["specification", "boundaries", "components", "threats", "projects"],
  "additionalProperties": false,
  "definitions": {
    "id": {
      "type": "string",
      "pattern": "^@[a-zA-Z0-9_]+$"
    },
    "references": {
      "type": "array",
      "items": { "type": "string" },
      "uniqueItems": true
    },
    "source": {
      "type": "object",
      "required": ["function","file","line"],
      "additionalProperties": false,
      "properties": {
        "function": { "type": "string" },
        "file": { "type": "string" },
        "line": { "type": "integer" }
      }
    },
    "call": {
      "type":"object",
      "required": ["source","destination"],
      "additionalProperties": false,
      "properties": {
        "source": { "type": "string" },
        "destination": { "type": "string" }
      }
    }
  },
  "properties": {
    "specification": {
      "type": "object",
      "required": ["name", "version"],
      "additionalProperties": false,
      "properties": {
        "name": { "type": "string", "pattern": "^ThreatSpec$" },
        "version": { "type": "string", "pattern": "^0\\.[0-9]+\\.[0-9]+$" }
      }
    },
    "document": {
      "type": "object",
      "additionalProperties": false,
      "properties": {
        "created": { "type": "integer" },
        "updated": { "type": "integer" }
      }
    },
    "boundaries": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" }
          }
        }
      }
    },
    "components": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" }
          }
        }
      }
    },
    "threats": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "additionalProperties": false,
          "required": ["name"],
          "properties": {
            "name": { "type": "string" },
            "description": { "type": "string" },
            "references": { "$ref": "#/definitions/references" }
          }
        }
      }
    },
    "projects": {
      "type": "object",
      "patternProperties": {
        "^@[a-zA-Z0-9_]+$": {
          "type": "object",
          "required": ["mitigations", "exposures", "transfers", "acceptances"],
          "properties": {
            "mitigations": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": ["mitigation","boundary","component","threat"],
                  "properities": {
                    "mitigation": { "type": "string" },
                    "boundary": { "$ref": "#/definitions/id" },
                    "component": { "$ref": "#/definitions/id" },
                    "threat": { "$ref": "#/definitions/id" },
                    "references": { "$ref": "#/definitions/references" },
                    "source": { "$ref": "#/definitions/source" }
                  }
                }
              }
            },
            "exposures": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": ["exposure","boundary","component","threat"],
                  "properities": {
                    "exposure": { "type": "string" },
                    "boundary": { "$ref": "#/definitions/id" },
                    "component": { "$ref": "#/definitions/id" },
                    "threat": { "$ref": "#/definitions/id" },
                    "references": { "$ref": "#/definitions/references" },
                    "source": { "$ref": "#/definitions/source" }
                  }
                }
              }
            },
            "transfers": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": ["transfer","boundary","component","threat"],
                  "properities": {
                    "transfer": { "type": "string" },
                    "boundary": { "$ref": "#/definitions/id" },
                    "component": { "$ref": "#/definitions/id" },
                    "threat": { "$ref": "#/definitions/id" },
                    "references": { "$ref": "#/definitions/references" },
                    "source": { "$ref": "#/definitions/source" }
                  }
                }
              }
            },
            "acceptances": {
              "type": "object",
              "patternProperties": {
                "^@[a-zA-Z0-9_]+$": {
                  "type": "object",
                  "additionalProperties": false,
                  "required": ["acceptance","boundary","component","threat"],
                  "properities": {
                    "acceptance": { "type": "string" },
                    "boundary": { "$ref": "#/definitions/id" },
                    "component": { "$ref": "#/definitions/id" },
                    "threat": { "$ref": "#/definitions/id" },
                    "references": { "$ref": "#/definitions/references" },
                    "source": { "$ref": "#/definitions/source" }
                  }
                }
              }
            }
          }
        }
      }
    },
    "callflow": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/call"
      }
    }
  }
}`
