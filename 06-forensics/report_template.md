# digital forensic investigation report

**classification:** [CONFIDENTIAL / INTERNAL / PUBLIC]

---

## document control

| field | detail |
|-------|--------|
| report reference | [REF-YYYY-NNN] |
| case identifier | [CASE_ID] |
| date of report | [DD/MM/YYYY] |
| investigator | [name, qualification] |
| organisation | [organisation name] |
| version | [1.0] |

### revision history

| version | date | author | changes |
|---------|------|--------|---------|
| 1.0 | [date] | [name] | initial report |

---

## 1. executive summary

[provide a brief, non-technical overview of the investigation, key findings, and conclusions. this section should be understandable by management and legal personnel without technical background.]

the investigation was initiated on [date] following [brief description of incident]. analysis of digital evidence revealed [high-level summary of findings]. based on the evidence examined, it is concluded that [key conclusion].

---

## 2. scope and objectives

### 2.1 scope

this investigation covers [define the boundaries of the investigation]:

- systems examined: [list]
- time period: [start date] to [end date]
- types of evidence: [network logs, system images, etc.]

### 2.2 objectives

the objectives of this investigation were to:

1. determine [specific objective]
2. identify [specific objective]
3. assess [specific objective]
4. preserve evidence for potential [legal/disciplinary] proceedings

### 2.3 limitations

- [any limitations on evidence access]
- [any time constraints]
- [any technical limitations]

---

## 3. methodology

### 3.1 evidence handling

all evidence was handled in accordance with ACPO guidelines for digital evidence. a chain of custody was maintained throughout the investigation (see appendix a).

### 3.2 tools and techniques

| tool | version | purpose |
|------|---------|---------|
| [tool name] | [version] | [what it was used for] |

### 3.3 analysis approach

1. **preservation** - evidence was acquired and verified using cryptographic hashing (sha256)
2. **identification** - relevant data sources were identified and catalogued
3. **analysis** - systematic examination of evidence was conducted
4. **documentation** - all findings were documented with supporting evidence

---

## 4. findings

### 4.1 finding 1: [title]

**severity:** [critical / high / medium / low]

**evidence reference:** [EVD-001]

[detailed technical description of the finding, supported by evidence. include relevant log entries, timestamps, and technical detail.]

### 4.2 finding 2: [title]

**severity:** [critical / high / medium / low]

**evidence reference:** [EVD-002]

[detailed description]

### 4.3 finding 3: [title]

[continue as needed]

---

## 5. timeline of events

[chronological reconstruction of events based on evidence analysis]

| date/time (UTC) | event | source | evidence ref |
|------------------|-------|--------|--------------|
| [timestamp] | [description] | [log/system] | [EVD-NNN] |

---

## 6. indicators of compromise

### 6.1 network indicators

| type | value | context |
|------|-------|---------|
| ip address | [x.x.x.x] | [where observed] |
| domain | [domain] | [where observed] |

### 6.2 host indicators

| type | value | context |
|------|-------|---------|
| file hash | [sha256] | [where found] |
| file path | [path] | [significance] |

---

## 7. conclusions

based on the evidence examined during this investigation:

1. [conclusion 1 - directly supported by findings]
2. [conclusion 2]
3. [conclusion 3]

[note: conclusions must be directly supported by the evidence presented in section 4. avoid speculation.]

---

## 8. recommendations

based on the findings of this investigation, the following actions are recommended:

### 8.1 immediate actions

1. [urgent remediation step]
2. [containment measure]

### 8.2 short-term improvements

1. [security improvement]
2. [process change]

### 8.3 long-term strategy

1. [strategic recommendation]
2. [policy change]

---

## appendix a: chain of custody

[reference chain_of_custody.md or include inline]

## appendix b: evidence inventory

| reference | description | hash (sha256) | acquired | by |
|-----------|-------------|----------------|----------|----|
| EVD-001 | [description] | [hash] | [date] | [name] |

## appendix c: glossary

| term | definition |
|------|------------|
| [term] | [plain english definition] |

---

**statement of truth**

i confirm that this report is a true and accurate record of my findings. the opinions expressed are based solely on the evidence examined and my professional experience.

signed: ________________________

name: [investigator name]

date: [date]

qualification: [relevant qualifications]
