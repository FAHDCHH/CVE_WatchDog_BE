# CVE Data Source API Audit Report

**Prepared:** March 27, 2026  
**Sources audited:** NVD CVE API · NVD CVE Change History API · EPSS API · CISA KEV


FAHDS NOTES : PRETTY MUCH EVERYTHING IS NEEDED FOR A FULLY COMPREHENSIVE DASHBOARD WITH MANY FILTER TYPES, similar to secalerts , and a comprehensive newsletter :*
 This forces me to consider the optimality of the db, and speed when querying, (indexiing, vues etc,) AND RECOVERY STRATEGIES IF IN THE MIDDLE OF THE TRANSOFRMATION THINGS GO; WRONG OR; SOME ELEMENTS GO WRONG; THERE SHOULD BE A RECOVERY THAT DOES NOT DLETE ALL AND STRART FROM SCRATCH , a recorery that onlly fetches what did no get transofred and loaded properly (either do that from the pipe_line logs table, or pipleline runs)

---

## SOURCE 1 — NVD CVE API

### 1. Endpoint URL

```
https://services.nvd.nist.gov/rest/json/cves/2.0
```

All requests use HTTP `GET`. Parameters are appended as query string arguments. The API key, when used, is passed as a request **header** (`apiKey:{key value}`), not as a URL parameter.

---

### 2. Authentication

API keys are optional. The public rate limit without an API key is 5 requests in a rolling 30-second window; the rate limit with an API key is 50 requests in a rolling 30-second window. Keys are free and obtained at `https://nvd.nist.gov/developers/request-an-api-key`. A valid email address is required to request one. Keys should not be shared with individuals or organizations other than the original requestor. For organizations where multiple employees transmit requests, the rate limits apply to the organization's proxy server or firewall, not per-individual user.

---

### 3. Rate Limits

|Mode|Limit|
|---|---|
|No API key|5 requests per rolling 30-second window|
|With API key|50 requests per rolling 30-second window|

NIST firewall rules put in place to prevent denial-of-service attacks can thwart an application if it exceeds the predetermined rate limit. The NVD's own best-practice guidance recommends sleeping 6 seconds between requests without a key, and 2 seconds with one. HTTP 403 is returned when the rate limit is exceeded.

---

### 4. Response Format

JSON (`application/json`), UTF-8 encoded. All datetime objects use ISO-8601 format with zero UTC offset. There is no native CSV output. The full schema is published at:

- CVE API JSON Schema: `https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema`
- CVSSv3.1 Schema: `https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.1.json`
- CVSSv3.0 Schema: `https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v3.0.json`
- CVSSv2.0 Schema: `https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v2.0.json`

---

### 5. Key Fields Returned

#### Top-level response envelope (always present)

| Field                 | Description                                            |
| --------------------- | ------------------------------------------------------ |
| `resultsPerPage`      | Number of CVE records returned in this response        |
| `startIndex`          | Zero-based offset of the first record in this response |
| `totalResults`        | Total matching CVEs across all pages                   |
| `format`              | Always `NVD_CVE`                                       |
| `version`             | API version string                                     |
| `timestamp`           | ISO-8601 datetime when the response was generated      |
| ==`vulnerabilities`== | ==Array of CVE objects==                               |
|                       |                                                        |

#### `cve` object — required fields NEED ALL

| Field              | Description                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------ |
| `id`               | CVE identifier (e.g., `CVE-2019-1010218`)                                                                                            |
| `sourceIdentifier` | Email/org identifier of the assigning CNA                                                                                            |
| `published`        | ISO-8601 datetime the CVE was published to NVD                                                                                       |
| `lastModified`     | ISO-8601 datetime the CVE was last modified                                                                                          |
| `vulnStatus`       | NVD analysis status — values: `Analyzed`, `Undergoing Analysis`, `Awaiting Analysis`, `Modified`, `Deferred`, `Rejected`, `Received` |
|                    |                                                                                                                                      |

#### `cve` object — optional fields (only present when data exists)

| Field                                    | Description                                        |
| ---------------------------------------- | -------------------------------------------------- |
| `evaluatorComment` NEED                  | NVD analyst supplementary comment                  |
| `evaluatorImpact` NEED                   | NVD analyst impact note                            |
| `evaluatorSolution` NEED                 | NVD analyst solution note                          |
| `cisaExploitAdd` DONT REALLY NEED        | Date the CVE was added to CISA KEV (ISO-8601 date) |
| `cisaActionDue` (not sure what it means) | BOD 22-01 remediation deadline for FCEB agencies   |
| `cisaRequiredAction` not sure            | CISA-mandated action text                          |
| `cisaVulnerabilityName` NEED             | CISA's display name for the vulnerability          |

#### `descriptions` (required)

|Field|Description|
|---|---|
|`lang`|ISO 639-1 two-letter language code (`en`, `es`)|
|`value`|Full vulnerability description text|

#### `metrics` (optional — only present for analyzed CVEs)

The `metrics` object contains sub-objects for each CVSS version that has data. Each sub-object includes `source`, `type` (`Primary` or `Secondary`), and the full `cvssData` block.

**`cvssMetricV2` fields:** (Generally not needed since it has not been produced since 2022, I dont think any vul from that time is still exploitable, I want to concern my self with newer ones)

| Field                            | Description                            |
| -------------------------------- | -------------------------------------- |
| `source` NEED                    | Organization that provided the score   |
| `type`                           | `Primary` or `Secondary`               |
| `cvssData.version` NEED          | Always `2.0`                           |
| `cvssData.vectorString`          | Full CVSS v2 vector string             |
| `cvssData.accessVector` NEED     | `NETWORK`, `ADJACENT_NETWORK`, `LOCAL` |
| `cvssData.accessComplexity`      | `LOW`, `MEDIUM`, `HIGH`                |
| `cvssData.authentication`        | `NONE`, `SINGLE`, `MULTIPLE`           |
| `cvssData.confidentialityImpact` | `NONE`, `PARTIAL`, `COMPLETE`          |
| `cvssData.integrityImpact`       | `NONE`, `PARTIAL`, `COMPLETE`          |
| `cvssData.availabilityImpact`    | `NONE`, `PARTIAL`, `COMPLETE`          |
| `cvssData.baseScore`             | Numeric score 0.0–10.0                 |
| `baseSeverity`                   | `LOW`, `MEDIUM`, `HIGH`                |
| `exploitabilityScore`            | Sub-score                              |
| `impactScore`                    | Sub-score                              |
| `acInsufInfo`                    | Boolean — insufficient info flag       |
| `obtainAllPrivilege`             | Boolean                                |
| `obtainUserPrivilege`            | Boolean                                |
| `obtainOtherPrivilege`           | Boolean                                |
| `userInteractionRequired`        | Boolean                                |

**`cvssMetricV31` / `cvssMetricV30` fields (structure identical between v3.0 and v3.1):** NEEDED , used only if v4 is not present

| Field                            | Description                                 |
| -------------------------------- | ------------------------------------------- |
| `source`                         | Providing organization                      |
| `type`                           | `Primary` or `Secondary`                    |
| `cvssData.version`               | `3.0` or `3.1`                              |
| `cvssData.vectorString`          | Full CVSS v3 vector string                  |
| `cvssData.attackVector`          | `NETWORK`, `ADJACENT`, `LOCAL`, `PHYSICAL`  |
| `cvssData.attackComplexity`      | `LOW`, `HIGH`                               |
| `cvssData.privilegesRequired`    | `NONE`, `LOW`, `HIGH`                       |
| `cvssData.userInteraction`       | `NONE`, `REQUIRED`                          |
| `cvssData.scope`                 | `UNCHANGED`, `CHANGED`                      |
| `cvssData.confidentialityImpact` | `NONE`, `LOW`, `HIGH`                       |
| `cvssData.integrityImpact`       | `NONE`, `LOW`, `HIGH`                       |
| `cvssData.availabilityImpact`    | `NONE`, `LOW`, `HIGH`                       |
| `cvssData.baseScore`             | Numeric score 0.0–10.0                      |
| `cvssData.baseSeverity`          | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `exploitabilityScore`            | Sub-score                                   |
| `impactScore`                    | Sub-score                                   |

**`cvssMetricV40` fields (CVSS v4.0):** ADOPTED as default  . NEED Every element if it is present
# CVSS v4.0 — Complete Metrics Reference (NEEEEEDED THE DEFAULT)

## Score Nomenclature

Table

|Label|Metrics Used|
|:--|:--|
|**CVSS-B**|Base only|
|**CVSS-BT**|Base + Threat|
|**CVSS-BE**|Base + Environmental|
|**CVSS-BTE**|Base + Threat + Environmental|

> Supplemental metrics **never affect** the numeric score.

---

## 1 — Base Metrics (Mandatory)

Table

| Metric                              | Abbr. | Values                | Description                                                                                                                                            |
| :---------------------------------- | :---- | :-------------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------- |
| Attack Vector                       | `AV`  | `N` / `A` / `L` / `P` | `N`=Network (internet-exploitable), `A`=Adjacent (same network/Bluetooth), `L`=Local (requires local access/logon), `P`=Physical (must touch hardware) |
| Attack Complexity                   | `AC`  | `L` / `H`             | `L`=Low — trivial, no special conditions. `H`=High — must bypass mitigations (ASLR, crypto, etc.)                                                      |
| Attack Requirements                 | `AT`  | `N` / `P`             | `N`=None — no target-side prerequisites. `P`=Present — requires race condition, specific config, or other target-side prerequisite                     |
| Privileges Required                 | `PR`  | `N` / `L` / `H`       | `N`=None — unauthenticated. `L`=Low — standard user. `H`=High — admin/root required                                                                    |
| User Interaction                    | `UI`  | `N` / `P` / `A`       | `N`=None — fully automated/wormable. `P`=Passive — victim does normal activity (visits page). `A`=Active — explicit non-routine action required        |
| Vulnerable System — Confidentiality | `VC`  | `H` / `L` / `N`       | Data exposure on the vulnerable system itself: `H`=total loss, `L`=limited, `N`=none                                                                   |
| Vulnerable System — Integrity       | `VI`  | `H` / `L` / `N`       | Modification on vulnerable system: `H`=total, `L`=limited, `N`=none                                                                                    |
| Vulnerable System — Availability    | `VA`  | `H` / `L` / `N`       | Disruption on vulnerable system: `H`=total downtime, `L`=degraded, `N`=none                                                                            |
| Subsequent System — Confidentiality | `SC`  | `H` / `L` / `N`       | Downstream data exposure (e.g. web app → host OS): `H`=total, `L`=limited, `N`=none                                                                    |
| Subsequent System — Integrity       | `SI`  | `H` / `L` / `N`       | Downstream modification (e.g. sandbox escape): `H`=total, `L`=limited, `N`=none                                                                        |
| Subsequent System — Availability    | `SA`  | `H` / `L` / `N`       | Downstream disruption (e.g. VM breakout → host crash): `H`=total, `L`=limited, `N`=none                                                                |

> **Key change from v3.1:** `Scope` is retired. Impacts split into **Vulnerable System** (`VC/VI/VA`) and **Subsequent System** (`SC/SI/SA`).

---

## 2 — Threat Metrics (Optional)

Table

|Metric|Abbr.|Values|Description|
|:--|:--|:--|:--|
|Exploit Maturity|`E`|`X` / `A` / `P` / `U`|`X`=Not Defined. `A`=Attacked — active exploitation confirmed. `P`=Proof-of-Concept — public PoC exists. `U`=Unreported — no known exploit|

> `Remediation Level` and `Report Confidence` from v3.1 are retired.

---

## 3 — Environmental Metrics (Optional)

### Security Requirements

Table

|Metric|Abbr.|Values|Description|
|:--|:--|:--|:--|
|Confidentiality Requirement|`CR`|`X` / `H` / `M` / `L`|How important is confidentiality of this asset to your org|
|Integrity Requirement|`IR`|`X` / `H` / `M` / `L`|How important is integrity of this asset to your org|
|Availability Requirement|`AR`|`X` / `H` / `M` / `L`|How important is uptime of this asset to your org|

### Modified Base Metrics (Overrides)

Table

|Metric|Abbr.|Values|Description|
|:--|:--|:--|:--|
|Modified Attack Vector|`MAV`|`X` / `N` / `A` / `L` / `P`|Override `AV` for your environment|
|Modified Attack Complexity|`MAC`|`X` / `L` / `H`|Override `AC` for your environment|
|Modified Attack Requirements|`MAT`|`X` / `N` / `P`|Override `AT` for your environment|
|Modified Privileges Required|`MPR`|`X` / `N` / `L` / `H`|Override `PR` for your environment|
|Modified User Interaction|`MUI`|`X` / `N` / `P` / `A`|Override `UI` for your environment|
|Modified Vulnerable System — Confidentiality|`MVC`|`X` / `N` / `L` / `H`|Override `VC` for your environment|
|Modified Vulnerable System — Integrity|`MVI`|`X` / `N` / `L` / `H`|Override `VI` for your environment|
|Modified Vulnerable System — Availability|`MVA`|`X` / `N` / `L` / `H`|Override `VA` for your environment|
|Modified Subsequent System — Confidentiality|`MSC`|`X` / `N` / `L` / `H`|Override `SC` for your environment|
|Modified Subsequent System — Integrity|`MSI`|`X` / `N` / `L` / `H` / `S`|Override `SI`. `S`=Safety impact (human safety)|
|Modified Subsequent System — Availability|`MSA`|`X` / `N` / `L` / `H` / `S`|Override `SA`. `S`=Safety impact (human safety)|

> `MSI:S` and `MSA:S` are for OT/ICS/IoT where exploitation could cause physical harm.

---

## 4 — Supplemental Metrics (Optional — Do NOT Affect Score)

Table (Keep too)

| Metric                        | Abbr. | Values                                    | Description                                                                                                              |
| :---------------------------- | :---- | :---------------------------------------- | :----------------------------------------------------------------------------------------------------------------------- |
| Safety                        | `S`   | `X` / `N` / `P`                           | `X`=Not Defined. `N`=Negligible. `P`=Present — meets IEC 61508 thresholds for physical harm                              |
| Automatable                   | `AU`  | `X` / `N` / `Y`                           | `N`=No — cannot automate all 4 kill-chain steps. `Y`=Yes — wormable / fully automatable                                  |
| Recovery                      | `R`   | `X` / `A` / `U` / `I`                     | `A`=Automatic self-recovery. `U`=User intervention required. `I`=Irrecoverable — permanent damage                        |
| Value Density                 | `V`   | `X` / `D` / `C`                           | `D`=Diffuse — limited resources per exploit. `C`=Concentrated — high-value target (domain controller, cloud admin)       |
| Vulnerability Response Effort | `RE`  | `X` / `L` / `M` / `H`                     | `L`=Low — simple firewall rule / auto-update. `M`=Medium — standard patch. `H`=High — re-architecture or rip-and-replace |
| Provider Urgency              | `U`   | `X` / `Clear` / `Green` / `Amber` / `Red` | Vendor's own urgency: `Clear`=Informational, `Green`=Reduced, `Amber`=Moderate, `Red`=Highest urgency                    |

---

## NVD API Response Fields (`cvssMetricV40`)

Table

|Field|Description|
|:--|:--|
|`source`|Scoring organization (e.g. `NIST`, `Microsoft`)|
|`type`|`Primary` (vendor/CNA) or `Secondary` (third-party reassessment)|
|`cvssData.version`|Always `4.0`|
|`cvssData.vectorString`|Full compressed metric string (e.g. `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`)|
|`cvssData.baseScore`|Final numeric score `0.0` – `10.0`|
|`cvssData.baseSeverity`|`NONE` / `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`|
|`exploitabilityScore`|Sub-score for ease of exploitation|
|`impactScore`|Sub-score for severity of impact|

---

## Quick Priority Cheat Sheet

Table

| Pattern                  | Meaning                                    | Action                           |
| :----------------------- | :----------------------------------------- | :------------------------------- |
| `AV:N` + `PR:N` + `UI:N` | Internet-facing, unauthenticated, no click | **Wormable — patch immediately** |
| `AT:N` + `AC:L`          | No prerequisites, trivial to exploit       | Easy to weaponize at scale       |
| `VC:H` + `VI:H` + `VA:H` | Total loss of CIA on vulnerable system     | Catastrophic if exploited        |
| `SC:H` / `SI:H` / `SA:H` | Host escape / downstream compromise        | Lateral movement risk            |
| `E:A`                    | Actively exploited in the wild             | **Emergency patching**           |
| `AU:Y`                   | Automatable / scalable                     | Expect mass exploitation         |
| `S:P`                    | Safety impact (physical harm)              | OT/ICS emergency                 |
| `U:Red`                  | Vendor rates maximum urgency               | Trust vendor assessment          |

| Field                                                   | Description                                 |
| ------------------------------------------------------- | ------------------------------------------- |
| `source`                                                | Providing organization                      |
| `type`                                                  | `Primary` or `Secondary`                    |
| `cvssData.version`                                      | `4.0`                                       |
| `cvssData.vectorString`                                 | Full CVSS v4 vector string                  |
| `cvssData.baseScore`                                    | Numeric score 0.0–10.0                      |
| `cvssData.baseSeverity`                                 | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| _(plus all v4.0 metric components per the v4.0 schema)_ | See CVSS v4.0 schema                        |

#### `weaknesses` (optional)

| Field                 | Description                                                          |
| --------------------- | -------------------------------------------------------------------- |
| `source`              | Providing organization                                               |
| `type`                | `Primary` or `Secondary`                                             |
| `description[].lang`  | Language code                                                        |
| `description[].value` | CWE ID string (e.g., `CWE-22`) or `NVD-CWE-Other` / `NVD-CWE-noinfo` |

#### `configurations` (optional — absent for unanalyzed CVEs--> keep that in mind even tho , if Im not mistaken I am not taking into consideration unalysed cve with no kev)

| Field                                      | Description                                            |
| ------------------------------------------ | ------------------------------------------------------ |
| `nodes[].operator`                         | `OR` or `AND`                                          |
| `nodes[].negate`                           | Boolean                                                |
| `nodes[].cpeMatch[].vulnerable`            | Boolean — whether this CPE is the vulnerable component |
| `nodes[].cpeMatch[].criteria`              | Full CPE 2.3 string                                    |
| `nodes[].cpeMatch[].matchCriteriaId`       | UUID for the match criteria record                     |
| `nodes[].cpeMatch[].versionStartIncluding` | Optional version bound                                 |
| `nodes[].cpeMatch[].versionStartExcluding` | Optional version bound                                 |
| `nodes[].cpeMatch[].versionEndIncluding`   | Optional version bound                                 |
| `nodes[].cpeMatch[].versionEndExcluding`   | Optional version bound                                 |

#### `references` (required — array may be empty)

| Field    | Description                                                                                                                                           |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `url`    | Reference URL                                                                                                                                         |
| `source` | Providing organization                                                                                                                                |
| `tags[]` | `Vendor Advisory`, `Third Party Advisory`, `Patch`, `Press/Media Coverage`, `Technical Description`, `VDB Entry`, `US Government Resource`, `Exploit` |

#### `cveTags` (optional)

|Field|Description|
|---|---|
|`sourceIdentifier`|Providing organization|
|`tags[]`|`disputed`, `unsupported-when-assigned`, `exclusively-hosted-service`|

#### `vendorComments` (optional)

|Field|Description|
|---|---|
|`organization`|Vendor name|
|`comment`|Full comment text|
|`lastModified`|ISO-8601 datetime|

---

### 6. Filtering Parameters
(This one s confusing )

| Parameter                             | Description                                                                                    |
| ------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `cveId`                               | Exact match on a single CVE ID                                                                 |
| `pubStartDate` + `pubEndDate`         | Filter by NVD publish date range (both required; max 120-day window; ISO-8601)                 |
| `lastModStartDate` + `lastModEndDate` | Filter by last modified date range (both required; max 120-day window; ISO-8601)               |
| `kevStartDate` + `kevEndDate`         | Filter by date the CVE was added to CISA KEV (both required; max 120-day window; ISO-8601)     |
| `cvssV2Severity`                      | `LOW`, `MEDIUM`, `HIGH`                                                                        |
| `cvssV3Severity`                      | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`                                                            |
| `cvssV4Severity`                      | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`                                                            |
| `cvssV2Metrics`                       | Full or partial CVSS v2 vector string                                                          |
| `cvssV3Metrics`                       | Full or partial CVSS v3 vector string                                                          |
| `cvssV4Metrics`                       | Full or partial CVSS v4 vector string                                                          |
| `cweId`                               | Filter to CVEs containing a specific CWE (e.g., `CWE-287`)                                     |
| `cpeName`                             | Filter to CVEs associated with a specific CPE 2.3 name                                         |
| `virtualMatchString`                  | Broader CPE match string filter (supports partial names)                                       |
| `versionStart` + `versionStartType`   | Used with `virtualMatchString` to define version range start                                   |
| `versionEnd` + `versionEndType`       | Used with `virtualMatchString` to define version range end                                     |
| `isVulnerable`                        | Boolean flag; requires `cpeName`; returns only CVEs where that CPE is the vulnerable component |
| `keywordSearch`                       | Keyword(s) matched against current English description (implicit AND; trailing wildcard)       |
| `keywordExactMatch`                   | Flag; requires `keywordSearch`; enforces exact phrase match                                    |
| `sourceIdentifier`                    | Filter to CVEs from a specific CNA source organization                                         |
| `hasKev`                              | Flag (no value); returns only CVEs in CISA KEV catalog                                         |
| `hasCertAlerts`                       | Flag; returns CVEs with a US-CERT Technical Alert                                              |
| `hasCertNotes`                        | Flag; returns CVEs with a CERT/CC Vulnerability Note                                           |
| `hasOval`                             | Flag; returns CVEs with MITRE OVAL data                                                        |
| `cveTag`                              | Filter by tag: `disputed`, `unsupported-when-assigned`, `exclusively-hosted-service`           |
| `noRejected`                          | Flag; excludes CVEs with status `REJECT` or `Rejected`                                         |
|                                       |                                                                                                |

> **Constraint:** CVSS version filter parameters are mutually exclusive across versions. `cvssV2Metrics` cannot be combined with `cvssV3Metrics` or `cvssV4Metrics`. Same applies to severity parameters.

> **Constraint:** All date range parameters have a maximum window of **120 consecutive days**. Queries spanning longer periods require multiple requests.

---

### 7. Pagination

Offset-based pagination using two parameters:

|Parameter|Default|Maximum|
|---|---|---|
|`resultsPerPage`|2,000|2,000|
|`startIndex`|0|N/A (zero-based index)|

The response always returns `totalResults`, `resultsPerPage`, and `startIndex`. To retrieve all results: loop, incrementing `startIndex` by `resultsPerPage` on each request, until `startIndex >= totalResults`. There is no cursor or token-based system — it is pure offset pagination. With 332,620 total CVEs in the database and a 2,000-record page limit, a full initial download requires a minimum of 167 requests.

---

### 8. Update Frequency

The APIs are updated as frequently as the NVD website, unlike the traditional feeds which had explicit update schedules. The `lastModified` field changes when: (1) NVD publishes a new CVE, (2) NVD changes the status of a published record after analysis, or (3) a CNA or other approved source modifies a published record. It does **not** change when NVD transitions a newly published CVE to "Undergoing Analysis" status, or when a CPE record previously associated with the CVE is modified. NVD best-practice recommends polling no more than once every two hours.

---

### 9. Known Limitations and Gotchas

**NVD enrichment backlog:** The NVD's pause of CVE data enrichment affects the incorporation of new CVEs into CPE, NIST CWE, and NIST CVSS scoring systems. A CVE may exist in the database with `vulnStatus: "Awaiting Analysis"` for an extended period — meaning no CVSS scores, no CWE, and no CPE configurations will be present. Newsletter pipelines must not assume scored data exists for recently published CVEs.

**CVSS v2 deprecation:** As of July 2022, NVD no longer generates new CVSS v2 data. Existing v2 data remains, but all new CVEs will only have v3.x or v4.0 scores (if analyzed at all).

**CISA KEV data is embedded in NVD responses:** The four CISA KEV fields (`cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, `cisaVulnerabilityName`) are included directly in the NVD API response when a CVE appears in the KEV catalog. However, see the cross-source discrepancy section — this is an incomplete subset of the KEV schema.

**Mutual exclusivity of CVSS version filters:** Cannot combine `cvssV2Metrics` with `cvssV3Metrics` in a single request.

**No numeric score threshold filter:** There is no `cvssScore-gt` or `cvssBaseScore-min` parameter. Score-based filtering requires fetching by severity band (LOW/MEDIUM/HIGH/CRITICAL) rather than a numeric threshold.

**Reliability:** Users often encounter HTTP 503 errors under load during peak usage hours. Pipeline design should implement retry logic with exponential backoff.

**Multi-CVE lookup not supported:** There is no batch endpoint. Each unique CVE requires its own request if fetched individually by ID.

**API key in header, not URL:** Despite some older documentation, the current v2.0 specification places the key in the HTTP request header as `apiKey:{value}`.

---

## SOURCE 2 — NVD CVE Change History API

### 1. Endpoint URL

```
https://services.nvd.nist.gov/rest/json/cvehistory/2.0
```

All requests use HTTP `GET`.

---

### 2. Authentication

Identical to the CVE API. API key is optional, passed in the request header. Same key obtained at `https://nvd.nist.gov/developers/request-an-api-key`.

---

### 3. Rate Limits

Identical to the CVE API: 5 requests per rolling 30-second window without a key; 50 requests per rolling 30-second window with a key.

---

### 4. Response Format

JSON (`application/json`), UTF-8 encoded. ISO-8601 datetimes. Schema published at:

```
https://csrc.nist.gov/schema/nvd/api/2.0/cve_history_api_json_2.0.schema
```

---

### 5. Key Fields Returned

#### Top-level response envelope

|Field|Description|
|---|---|
|`resultsPerPage`|Change events returned in this response|
|`startIndex`|Zero-based offset|
|`totalResults`|Total matching change events|
|`format`|Always `NVD_CVEHistory`|
|`version`|API version string|
|`timestamp`|Response generation datetime|
|`cveChanges`|Array of change event objects|

#### `change` object (all fields required)

| Field              | Description                                            |
| ------------------ | ------------------------------------------------------ |
| `cveId`            | The CVE identifier that changed                        |
| `eventName`        | Type of change event (see table below)                 |
| `cveChangeId`      | UUID uniquely identifying this change event            |
| `sourceIdentifier` | Organization that triggered the change                 |
| `created`          | ISO-8601 datetime the change event was recorded        |
| `details`          | Array of individual field-level changes (may be empty) |

#### `details` array entries

| Field      | Description                                                                                                |
| ---------- | ---------------------------------------------------------------------------------------------------------- |
| `action`   | `Added`, `Changed`, or `Removed`                                                                           |
| `type`     | Type of data that changed (e.g., `CVSS V3.1`, `CWE`, `CPE Configuration`, `Reference Type`, `Description`) |
| `oldValue` | Previous value (present when `action` is `Changed` or `Removed`)                                           |
| `newValue` | New value (present when `action` is `Added` or `Changed`)                                                  |

#### Valid `eventName` values (At this point I am rethinking my deciosn of nt including under analysis cve's ,they will be included into the db, just not have a priority in the dhashoboard,  the cve status will be present at the dashboard , maybe : as for ones that are not yet even analysed , the will not  be included)

| Event Name                                             | Meaning                                                  |
| ------------------------------------------------------ | -------------------------------------------------------- |
| `CVE Received`                                         | CVE published to NVD; not yet analyzed                   |
| `Initial Analysis`                                     | NVD enriches with CVSS, CWE, CPE, reference tags         |
| `Reanalysis`                                           | NVD re-analyzes a previously analyzed record             |
| `CVE Modified`                                         | An approved CNA modifies a published record              |
| `Modified Analysis`                                    | NVD re-analyzes after a CNA modification                 |
| `CVE Translated`                                       | A non-English translation is added                       |
| `Vendor Comment`                                       | A vendor comment is added                                |
| `CVE Source Update`                                    | Metadata about a contributing source is updated          |
| `CPE Deprecation Remap`                                | CPE match criteria updated due to CPE dictionary changes |
| `CWE Remap`                                            | Weakness association updated outside of analysis cycle   |
| `Reference Tag Update`                                 | A reference URL's tag classification is updated          |
| `CVE Rejected`                                         | An approved source rejects the CVE                       |
| `CVE Unrejected` how would I deal with this little one | A previously rejected CVE is republished                 |
| `CVE CISA KEV Update`                                  | CISA KEV data for the associated CVE was updated         |

---

### 6. Filtering Parameters

|Parameter|Description|
|---|---|
|`cveId`|Returns complete change history for a single CVE|
|`changeStartDate` + `changeEndDate`|Filter by the date of the change event (both required; max 120-day window; ISO-8601)|
|`eventName`|Filter to a specific event type (one value per request; URL-encode spaces as `%20`)|
|`resultsPerPage`|Max 5,000 (default 5,000)|
|`startIndex`|Zero-based offset|

> **Distinction:** `changeStartDate`/`changeEndDate` filter by the date of the _change event_, not by `lastModified` on the CVE record. These are distinct timestamps.

---

### 7. Pagination

Identical offset-based mechanism as the CVE API, but with a higher per-page maximum of 5,000 change events. Parameters: `resultsPerPage` (default/max: 5,000) and `startIndex` (zero-based).

---

### 8. Update Frequency

Change events are recorded in real time as CVE records are modified. The `CVE CISA KEV Update` event fires whenever KEV fields on a CVE record are modified, including silent ransomware flag changes.

---

### 9. Known Limitations and Gotchas

**No score-based filtering:** There is no way to filter change history by CVSS score threshold. You can filter by `eventName=Initial Analysis` to catch newly scored CVEs, but there is no way to filter for "only changes that affected the CVSS score."

**Early records are sparse:** Records prior to 2015 may have incomplete change history due to the evolution of NVD's data fidelity over the decades.

**Only one `eventName` per request:** Cannot combine multiple event types in a single request. To monitor both `Initial Analysis` and `Reanalysis` events, two separate requests are required.

**120-day maximum window** applies to `changeStartDate`/`changeEndDate` identically to the CVE API.

**`CVE CISA KEV Update` events are the canonical NVD signal for KEV changes** — but NVD may lag behind the CISA canonical source.

---

## SOURCE 3 — EPSS API

### 1. Endpoint URLs

**Primary API (paginated JSON):**

```
https://api.first.org/data/v1/epss
```

**Bulk CSV download (full dataset for a specific date):**

```
https://epss.empiricalsecurity.com/epss_scores-YYYY-MM-DD.csv.gz
```

Historic EPSS scores are available back to **April 14, 2021**.

---

### 2. Authentication

No authentication. All endpoints are unauthenticated and open. There is no API key system. FIRST Members may contact the infrastructure team via the Support Portal to request increased limits.

---

### 3. Rate Limits

|Mode|Limit|
|---|---|
|Public (unauthenticated)|1,000 requests per minute|

HTTP 429 is returned when the limit is exceeded. Abusive behavior may result in a temporary block across all API endpoints.

---

### 4. Response Format

**API endpoint:** JSON by default. Also supports YAML (`.yml`), XML (`.xml`), CSV (`.csv`), XLS (`.xls`), XLSX (`.xlsx`) via URL extension or `Accept:` header. UTF-8 encoding. Gzip compression supported via `Accept-Encoding: compress, gzip`.

**Bulk download:** Gzip-compressed CSV (`.csv.gz`).

---

### 5. Key Fields Returned

#### Response envelope (with `envelope=true`)

|Field|Description|
|---|---|
|`status`|HTTP status text|
|`status-code`|HTTP status code|
|`version`|API version|
|`access`|Cache/access policy string|
|`total`|Total matching records|
|`offset`|Current pagination offset|
|`limit`|Current page size limit|
|`data`|Array of EPSS score objects|

#### Per-CVE `data` entry (default `public` scope)

|Field|Description|
|---|---|
|`cve`|CVE identifier string (e.g., `CVE-2021-40438`)|
|`epss`|EPSS probability score as a decimal string (e.g., `"0.972240000"`) — probability of exploitation in the wild within 30 days|
|`percentile`|Relative percentile among all scored CVEs (e.g., `"1.000000000"` = top of distribution)|
|`date`|The scoring date in `YYYY-MM-DD` format|

**With `scope=time-series`:** Returns the same four fields per day, for up to 30 days of history per CVE.

**Bulk CSV columns:** `cve`, `epss`, `percentile` — one row per CVE.

---

### 6. Filtering Parameters

|Parameter|Type|Description|
|---|---|---|
|`cve`|string|One or more CVE IDs, comma-separated. Maximum 2,000 characters total (including commas).|
|`date`|date (`YYYY-MM-DD`)|Returns historical scores for that specific date (available from 2021-04-14). Not affected by `days`.|
|`days`|int|Returns CVEs first scored within the last N days (starting at 1). Not affected by `date`.|
|`epss-gt`|decimal|Returns only CVEs with EPSS score greater than or equal to this value.|
|`epss-lt`|decimal|Returns only CVEs with EPSS score less than or equal to this value.|
|`percentile-gt`|decimal|Returns only CVEs with percentile greater than or equal to this value.|
|`percentile-lt`|decimal|Returns only CVEs with percentile less than or equal to this value.|
|`q`|string|Free-text partial match on CVE ID.|
|`order`|string|Sort field. Use `!epss` for descending by score, `!percentile` for descending by percentile.|
|`scope`|string|`public` (default) or `time-series` (30-day score history per CVE).|
|`limit`|integer|Page size, 0–10,000.|
|`offset`|integer|Pagination offset (zero-based).|
|`fields`|string|Comma-separated list of field names to return (reduces payload).|
|`envelope`|boolean|`true`/`false` — wraps response in metadata object.|
|`pretty`|boolean|`true`/`false` — human-readable formatting.|

---

### 7. Pagination

Default `limit` is 100 if not specified; maximum is 10,000. The `total` field (or `X-Total` response header) indicates the total number of matching records. Increment `offset` by `limit` on each subsequent request until all records are retrieved. There is no cursor — it is pure offset pagination. For the full dataset, use the bulk CSV download instead.

---

### 8. Update Frequency

Scores are recalculated and published **daily**. Each day's score reflects the model's current estimate of 30-day exploitation probability. A CVE's score can change significantly day-to-day as new signals are incorporated. The `date` field in the response reflects the scoring date.

---

### 9. Known Limitations and Gotchas

**No CVSS data, no vulnerability descriptions:** EPSS returns only `cve`, `epss`, `percentile`, and `date`. All vulnerability metadata must be fetched from NVD separately and joined on CVE ID.

**Score is a probability, not a severity:** EPSS does not measure severity or impact. A CVE with EPSS of 0.95 may have a CVSS score of 4.0; a critical CVSS 10.0 may have EPSS of 0.001. These are orthogonal signals.

**Scores are decimal strings, not floats:** The `epss` and `percentile` fields are returned as string-formatted decimals (e.g., `"0.972240000"`). Numeric comparisons require parsing.

**Batch CVE lookup is character-limited:** The `cve` parameter is capped at 2,000 total characters. For large batch lookups, multiple requests or the bulk CSV download are required.

**Bulk CSV URL host differs from the API host:** The paginated JSON API lives at `api.first.org`; the bulk CSV download lives at `epss.empiricalsecurity.com`. Both are authoritative.

**No filtering by CVE publication date:** There is no `pubStartDate`/`pubEndDate` equivalent. The `days` parameter counts from first EPSS scoring, not from CVE publication.

**`time-series` scope returns up to 30 days only:** For longer historical trend analysis, request individual historical dates via the `date` parameter.

---

## SOURCE 4 — CISA KEV

### 1. Endpoint URLs

**Canonical JSON:**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

**Canonical CSV:**

```
https://www.cisa.gov/sites/default/files/csv/known_exploited_vulnerabilities.csv
```

**Official GitHub mirror** (more reliable for programmatic access):

```
https://github.com/cisagov/kev-data
```

**JSON schema:**

```
https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities_schema.json
```

There is **no query API** for CISA KEV. Both URLs deliver the complete catalog as a single flat file. There is no endpoint for fetching individual CVEs, filtering by date, or paginating.

---

### 2. Authentication

None required. Fully public and unauthenticated. No registration, no API key, no rate limit documentation is published by CISA. The data is licensed under **CC0** (universal public domain).

---

### 3. Rate Limits

CISA does not document explicit rate limits. The `cisa.gov` domain has been known to return HTTP 403 responses to automated crawlers. The GitHub mirror is generally more reliable for programmatic access.

---

### 4. Response Format

Two formats, delivered as complete flat file downloads:

**JSON:** A single JSON object with catalog metadata and a `vulnerabilities` array.

**CSV:** A flat file where each row is one KEV entry. Columns:

```
cveID, vendorProject, product, vulnerabilityName, dateAdded, shortDescription,
requiredAction, dueDate, knownRansomwareCampaignUse, notes, cwes
```

---

### 5. Key Fields Returned

#### JSON top-level metadata

|Field|Description|
|---|---|
|`title`|Catalog title string|
|`catalogVersion`|Semantic version of the KEV catalog|
|`dateReleased`|ISO-8601 datetime of the last catalog update|
|`count`|Total number of entries in `vulnerabilities` array|
|`vulnerabilities`|Array of vulnerability objects|

#### Per-entry `vulnerabilities` object — all fields

| Field                                | Type             | Description                                                                                                      |
| ------------------------------------ | ---------------- | ---------------------------------------------------------------------------------------------------------------- |
| `cveID`                              | string           | CVE identifier (e.g., `CVE-2021-27104`). Primary join key to NVD and EPSS.                                       |
| `vendorProject`                      | string           | Vendor or project name (e.g., `Microsoft`, `Cisco`, `Apache`)                                                    |
| `product`                            | string           | Affected product name (e.g., `Windows`, `IOS XE`, `Log4j`)                                                       |
| `vulnerabilityName`                  | string           | CISA's descriptive name for the vulnerability                                                                    |
| `dateAdded`                          | string           | Date the entry was added to KEV, in `YYYY-MM-DD` format                                                          |
| `shortDescription`                   | string           | Brief description of the vulnerability type and impact                                                           |
| `requiredAction`                     | string           | Remediation action required by CISA                                                                              |
| `dueDate`                            | string           | Remediation deadline in `YYYY-MM-DD` format — binding for FCEB agencies under BOD 22-01; advisory for all others |
| `knownRansomwareCampaignUse`         | string           | `"Known"` or `"Unknown"` — added by CISA in October 2023                                                         |
| `notes`                              | string           | Semicolon-separated list of reference URLs                                                                       |
| `cwes` this I believe is not needed  | array of strings | CWE identifiers (e.g., `["CWE-94"]`). Late addition; may be absent or empty on older entries.                    |

---

### 6. Filtering Parameters

**None.** The entire catalog is returned in every download. All filtering must be performed client-side after download.

---

### 7. Pagination

**None.** The entire catalog (~1,553 entries as of March 2026) is delivered in a single response.

---

### 8. Update Frequency

Updated whenever new or updated KEV entries are available — typically weekdays during US Eastern business hours. No guaranteed schedule. Additions can come in batches of one to dozens of entries. Existing entries can also be **silently modified** (specifically `knownRansomwareCampaignUse`) without any public announcement. The only reliable way to detect silent updates is to diff successive downloads or monitor the GitHub commit history.

---

### 9. Known Limitations and Gotchas

**No query API, no delta feed:** No mechanism to fetch only entries added or changed since a given date. Every poll retrieves the full catalog. Pipelines must implement their own diffing logic.

**Silent field updates are not tracked in the catalog itself:** CISA has been modifying JSON file entries without corresponding security advisories, effectively hiding material changes. The GitHub mirror at `cisagov/kev-data` provides commit history and is the most practical way to audit changes over time.

**`cisa.gov` URLs may return 403:** Use the GitHub raw URL or GitHub API for reliable programmatic access:

```
https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
```

**`cwes` field is a late addition:** May be absent or empty on older KEV entries. Do not treat its absence as confirmation that no CWE is associated.

**`knownRansomwareCampaignUse` only has two states:** `"Known"` or `"Unknown"`. There is no `"Not Applicable"` or `"No"`. `"Unknown"` means CISA has not confirmed ransomware use, not that it has been ruled out.

**No CVSS data included:** All severity scores must be fetched from NVD separately.

**`dueDate` is only binding for FCEB agencies:** For non-government organizations, it is advisory. Newsletter framing should clarify this distinction.

---

## CROSS-SOURCE DISCREPANCIES AND INTEGRATION FLAGS

### 1. KEV Data is Duplicated Between NVD and CISA (with lag)

NVD embeds four CISA KEV fields directly in the CVE API response: `cisaExploitAdd`, `cisaActionDue`, `cisaRequiredAction`, and `cisaVulnerabilityName`. However, the NVD's KEV data may lag the canonical CISA source. Additionally, NVD's embedded fields are a **subset** of the full KEV schema — the following KEV fields are **not** present in the NVD API response:

- `knownRansomwareCampaignUse`
- `shortDescription`
- `notes`
- `cwes`

A pipeline that relies solely on NVD for KEV data will miss the ransomware flag and KEV-specific notes fields.

---

### 2. Silent KEV Updates Are Not Reliably Surfaced by NVD Change History

When CISA silently flips `knownRansomwareCampaignUse` from `"Unknown"` to `"Known"`, NVD may or may not generate a `CVE CISA KEV Update` change event, and even if it does, there is a lag. For a newsletter tracking ransomware-related escalations, polling the raw CISA KEV JSON directly (or its GitHub mirror) and performing your own diffing is the most reliable approach.

---

### 3. EPSS Coverage vs. NVD Coverage

EPSS covers a different universe of CVEs than NVD at any given moment. New CVEs may exist in NVD (`vulnStatus: "Awaiting Analysis"`) for days or weeks before EPSS generates a score. Conversely, EPSS may retain scores for CVEs that NVD has marked `Rejected`. When joining on CVE ID, expect null EPSS values for recently published CVEs, and expect EPSS entries for CVEs with no current NVD score.

---

### 4. No Score Threshold Filter in NVD; EPSS Has One

NVD's filtering is severity-band-based (`cvssV3Severity=CRITICAL`) rather than numeric. EPSS provides `epss-gt` and `percentile-gt` for true threshold filtering. For a newsletter that wants "all CVEs with CVSS ≥ 9.0," note that NVD `cvssV3Severity=CRITICAL` captures scores ≥ 9.0 by definition, but CVSS 8.x falls under `HIGH` and cannot be numerically split from lower HIGH scores server-side.

---

### 5. Field Name Inconsistency: `cveID` vs. `cve` vs. `id`

The join key is the CVE identifier, but each source uses a different field name:

|Source|Field Name|
|---|---|
|NVD CVE API|`id`|
|EPSS API|`cve`|
|CISA KEV|`cveID`|

Pipeline code must normalize this field name when joining records across sources.

---

### 6. Date Format Inconsistency

|Source|Date Format|Example|
|---|---|---|
|NVD CVE API|Full ISO-8601 with time and UTC offset|`2021-08-04T13:00:00.000Z`|
|NVD date filter parameters|Full ISO-8601 required|`2021-08-04T00:00:00.000Z`|
|CISA KEV|Simple date string, no time component|`2021-11-03`|
|EPSS|Simple date string, no time component|`2022-02-28`|

All NVD date filter parameters require the full ISO-8601 format including the `T` separator and timezone designator. Passing a bare date string will result in an error or unexpected behavior.