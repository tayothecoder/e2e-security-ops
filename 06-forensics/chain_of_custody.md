# chain of custody record

## case information

| field | detail |
|-------|--------|
| case id | [CASE_ID] |
| case name | [brief description] |
| lead investigator | [name] |
| date opened | [DD/MM/YYYY] |

---

## evidence log

### evidence item [EVD-001]

| field | detail |
|-------|--------|
| description | [what the evidence is] |
| type | [disk image / log file / pcap / memory dump / etc] |
| source system | [hostname / ip / location] |
| original location | [filesystem path or physical location] |
| date/time acquired | [DD/MM/YYYY HH:MM UTC] |
| acquired by | [name] |
| method of acquisition | [tool and technique used] |
| original hash (sha256) | [hash value] |
| verified hash (sha256) | [hash value - must match original] |
| storage location | [where the evidence is stored] |

#### transfer log

| date/time | from | to | purpose | signature |
|-----------|------|----|---------|-----------|
| [timestamp] | [name] | [name] | [reason for transfer] | [initials] |

---

### evidence item [EVD-002]

| field | detail |
|-------|--------|
| description | |
| type | |
| source system | |
| original location | |
| date/time acquired | |
| acquired by | |
| method of acquisition | |
| original hash (sha256) | |
| verified hash (sha256) | |
| storage location | |

#### transfer log

| date/time | from | to | purpose | signature |
|-----------|------|----|---------|-----------|
| | | | | |

---

## notes

- all evidence must be stored in a secure, access-controlled location
- any access to evidence must be logged in the transfer log above
- hashes must be verified each time evidence is accessed
- evidence must not be modified; work only on forensic copies
- maintain this document as part of the case file

## integrity verification log

| date | verified by | evidence ref | hash match | notes |
|------|-------------|--------------|------------|-------|
| [date] | [name] | EVD-001 | yes/no | [any notes] |
