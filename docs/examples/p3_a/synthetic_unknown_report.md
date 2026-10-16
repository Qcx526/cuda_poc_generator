# Deterministic CVE Oracle Report — P3-A

| Field | Value |
| --- | --- |
| "Target CVE" | "CVE-2099-0001" |
| "Oracle" | "SYNTHETIC-five-category-oracle-v1" |
| "Evidence domain" | "SYNTHETIC" |
| "Plan SHA-256" | "6a4f939fc2d973482793db096e02490fa6c80f10408f271f284e89d17f7be357" |
| "Corpus manifest SHA-256" | null |
| "Environment eligibility" | "UNKNOWN" |
| "Condition aggregate" | "UNKNOWN" |
| "Oracle verdict" | "UNKNOWN" |
| "Real CVE verification" | "NOT&#95;VERIFIED" |
| "Execution authorized by this report" | false |

## Interpretation and decision rule

| Field | Value |
| --- | --- |
| "Standard ID" | "SYNTHETIC&#95;ALL&#95;REQUIRED&#95;V1" |
| "Predeclared standard" | "SYNTHETIC: every necessary category must have bound exact-field evidence." |
| "Review reference" | "SYNTHETIC&#95;TEST&#95;REVIEW&#95;ONLY" |
| "Eligibility reasons" | &#91;"environment: required evidence reference is missing"&#93; |
| "Decision reasons" | &#91;"insufficient eligibility or necessary objective evidence"&#93; |

**SYNTHETIC: any VERIFIED verdict proves only the synthetic Oracle rules.**
No real CVE reproduction or real vulnerability verification is established.
Real CVE verification remains NOT_VERIFIED.

A crash, signal, Sanitizer finding, nonzero exit or exit zero alone does not prove a specific CVE.
The report preserves the Oracle output; it supplies no additional execution observations.

## Claim, public sources and unknowns

No VulnerabilityClaim was supplied. Affected versions, fixes and public facts are UNKNOWN.

## Bound environment and identities

| Field | Value |
| --- | --- |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "tool&#95;sha256" | {"fixture": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"} |

| Field | Value |
| --- | --- |
| "Observed context with original artifact identities" | {} |

Actual tool, driver and platform versions appear only when the following
condition observations contain corresponding measured fields. Missing observations remain UNKNOWN.

## Trigger conditions and observed values

### "anomaly"

| Field | Value |
| --- | --- |
| "Category" | "ANOMALY" |
| "Subject" | "synthetic.anomaly" |
| "Required" | true |
| "Applicability" | "APPLICABLE" |
| "Predicate" | "EQUALS" |
| "Expected relation" | "EQUALS" |
| "Expected value" | "SYNTHETIC&#95;BOUND&#95;MEMORY&#95;WRITE" |
| "Minimum inclusive" | null |
| "Maximum exclusive" | null |
| "Evidence requirement" | {"completeness&#95;required": true, "evidence&#95;source": "SYNTHETIC", "evidence&#95;type": "PROCESS", "method": "SYNTHETIC&#95;FACT", "reference&#95;ids": &#91;"anomaly-evidence"&#93;, "scope": "SYNTHETIC"} |
| "Provenance source IDs" | &#91;"synthetic-reviewed-test-rule-v1"&#93; |
| "Status" | "SATISFIED" |
| "Reason" | "typed equality against original structured field" |
| "Observed values" | &#91;"SYNTHETIC&#95;BOUND&#95;MEMORY&#95;WRITE"&#93; |
| "Used reference IDs" | &#91;"anomaly-evidence"&#93; |

### "entry"

| Field | Value |
| --- | --- |
| "Category" | "ENTRY&#95;BEHAVIOR" |
| "Subject" | "synthetic.entry" |
| "Required" | true |
| "Applicability" | "APPLICABLE" |
| "Predicate" | "EQUALS" |
| "Expected relation" | "EQUALS" |
| "Expected value" | "SYNTHETIC&#95;REVIEWED&#95;ENTRY" |
| "Minimum inclusive" | null |
| "Maximum exclusive" | null |
| "Evidence requirement" | {"completeness&#95;required": true, "evidence&#95;source": "SYNTHETIC", "evidence&#95;type": "PROCESS", "method": "SYNTHETIC&#95;FACT", "reference&#95;ids": &#91;"entry-evidence"&#93;, "scope": "SYNTHETIC"} |
| "Provenance source IDs" | &#91;"synthetic-reviewed-test-rule-v1"&#93; |
| "Status" | "SATISFIED" |
| "Reason" | "typed equality against original structured field" |
| "Observed values" | &#91;"SYNTHETIC&#95;REVIEWED&#95;ENTRY"&#93; |
| "Used reference IDs" | &#91;"entry-evidence"&#93; |

### "environment"

| Field | Value |
| --- | --- |
| "Category" | "ENVIRONMENT" |
| "Subject" | "synthetic.environment" |
| "Required" | true |
| "Applicability" | "APPLICABLE" |
| "Predicate" | "EQUALS" |
| "Expected relation" | "EQUALS" |
| "Expected value" | "12.8.90" |
| "Minimum inclusive" | null |
| "Maximum exclusive" | null |
| "Evidence requirement" | {"completeness&#95;required": true, "evidence&#95;source": "SYNTHETIC", "evidence&#95;type": "PLATFORM", "method": "SYNTHETIC&#95;FACT", "reference&#95;ids": &#91;&#93;, "scope": "SYNTHETIC"} |
| "Provenance source IDs" | &#91;"synthetic-reviewed-test-rule-v1"&#93; |
| "Status" | "UNKNOWN" |
| "Reason" | "required evidence reference is missing" |
| "Observed values" | &#91;&#93; |
| "Used reference IDs" | &#91;&#93; |

### "identity"

| Field | Value |
| --- | --- |
| "Category" | "IDENTITY" |
| "Subject" | "synthetic.identity" |
| "Required" | true |
| "Applicability" | "APPLICABLE" |
| "Predicate" | "EQUALS" |
| "Expected relation" | "EQUALS" |
| "Expected value" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "Minimum inclusive" | null |
| "Maximum exclusive" | null |
| "Evidence requirement" | {"completeness&#95;required": true, "evidence&#95;source": "SYNTHETIC", "evidence&#95;type": "IDENTITY", "method": "SYNTHETIC&#95;FACT", "reference&#95;ids": &#91;"identity-evidence"&#93;, "scope": "SYNTHETIC"} |
| "Provenance source IDs" | &#91;"synthetic-reviewed-test-rule-v1"&#93; |
| "Status" | "SATISFIED" |
| "Reason" | "typed equality against original structured field" |
| "Observed values" | &#91;"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"&#93; |
| "Used reference IDs" | &#91;"identity-evidence"&#93; |

### "root&#95;cause"

| Field | Value |
| --- | --- |
| "Category" | "ROOT&#95;CAUSE" |
| "Subject" | "synthetic.root&#95;cause" |
| "Required" | true |
| "Applicability" | "APPLICABLE" |
| "Predicate" | "EQUALS" |
| "Expected relation" | "EQUALS" |
| "Expected value" | "SYNTHETIC&#95;ROOT&#95;CAUSE&#95;BOUND" |
| "Minimum inclusive" | null |
| "Maximum exclusive" | null |
| "Evidence requirement" | {"completeness&#95;required": true, "evidence&#95;source": "SYNTHETIC", "evidence&#95;type": "ROOT&#95;CAUSE", "method": "SYNTHETIC&#95;FACT", "reference&#95;ids": &#91;"root&#95;cause-evidence"&#93;, "scope": "SYNTHETIC"} |
| "Provenance source IDs" | &#91;"synthetic-reviewed-test-rule-v1"&#93; |
| "Status" | "SATISFIED" |
| "Reason" | "typed equality against original structured field" |
| "Observed values" | &#91;"SYNTHETIC&#95;ROOT&#95;CAUSE&#95;BOUND"&#93; |
| "Used reference IDs" | &#91;"root&#95;cause-evidence"&#93; |

## Exact evidence references

| Field | Value |
| --- | --- |
| "reference&#95;id" | "anomaly-evidence" |
| "domain" | "SYNTHETIC" |
| "cve&#95;id" | "CVE-2099-0001" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "artifact&#95;file" | "fixture.json" |
| "artifact&#95;sha256" | "e24dcde7a4a3d69defb63d20b53d887176cca718239387866192eec43e026652" |
| "json&#95;pointer" | "/anomaly/kind" |
| "original&#95;source" | "SYNTHETIC&#95;FIXTURE" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "tool&#95;role" | "fixture" |
| "tool&#95;sha256" | "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" |
| "collection&#95;method" | "p3a-synthetic-1.0" |
| "scope" | "SYNTHETIC" |
| "evidence&#95;type" | "PROCESS" |

| Field | Value |
| --- | --- |
| "reference&#95;id" | "entry-evidence" |
| "domain" | "SYNTHETIC" |
| "cve&#95;id" | "CVE-2099-0001" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "artifact&#95;file" | "fixture.json" |
| "artifact&#95;sha256" | "e24dcde7a4a3d69defb63d20b53d887176cca718239387866192eec43e026652" |
| "json&#95;pointer" | "/entry/path" |
| "original&#95;source" | "SYNTHETIC&#95;FIXTURE" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "tool&#95;role" | "fixture" |
| "tool&#95;sha256" | "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" |
| "collection&#95;method" | "p3a-synthetic-1.0" |
| "scope" | "SYNTHETIC" |
| "evidence&#95;type" | "PROCESS" |

| Field | Value |
| --- | --- |
| "reference&#95;id" | "environment-evidence" |
| "domain" | "SYNTHETIC" |
| "cve&#95;id" | "CVE-2099-0001" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "artifact&#95;file" | "fixture.json" |
| "artifact&#95;sha256" | "e24dcde7a4a3d69defb63d20b53d887176cca718239387866192eec43e026652" |
| "json&#95;pointer" | "/environment/version" |
| "original&#95;source" | "SYNTHETIC&#95;FIXTURE" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "tool&#95;role" | "fixture" |
| "tool&#95;sha256" | "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" |
| "collection&#95;method" | "p3a-synthetic-1.0" |
| "scope" | "SYNTHETIC" |
| "evidence&#95;type" | "PLATFORM" |

| Field | Value |
| --- | --- |
| "reference&#95;id" | "identity-evidence" |
| "domain" | "SYNTHETIC" |
| "cve&#95;id" | "CVE-2099-0001" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "artifact&#95;file" | "fixture.json" |
| "artifact&#95;sha256" | "e24dcde7a4a3d69defb63d20b53d887176cca718239387866192eec43e026652" |
| "json&#95;pointer" | "/identity/candidate&#95;sha256" |
| "original&#95;source" | "SYNTHETIC&#95;FIXTURE" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "tool&#95;role" | "fixture" |
| "tool&#95;sha256" | "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" |
| "collection&#95;method" | "p3a-synthetic-1.0" |
| "scope" | "SYNTHETIC" |
| "evidence&#95;type" | "IDENTITY" |

| Field | Value |
| --- | --- |
| "reference&#95;id" | "root&#95;cause-evidence" |
| "domain" | "SYNTHETIC" |
| "cve&#95;id" | "CVE-2099-0001" |
| "request&#95;id" | "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" |
| "run&#95;id" | "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" |
| "artifact&#95;file" | "fixture.json" |
| "artifact&#95;sha256" | "e24dcde7a4a3d69defb63d20b53d887176cca718239387866192eec43e026652" |
| "json&#95;pointer" | "/root&#95;cause/binding" |
| "original&#95;source" | "SYNTHETIC&#95;FIXTURE" |
| "platform&#95;environment&#95;id" | "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd" |
| "platform&#95;probe&#95;id" | "synthetic-probe-v1" |
| "snapshot&#95;sha256" | "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" |
| "candidate&#95;sha256" | "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" |
| "tool&#95;role" | "fixture" |
| "tool&#95;sha256" | "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" |
| "collection&#95;method" | "p3a-synthetic-1.0" |
| "scope" | "SYNTHETIC" |
| "evidence&#95;type" | "ROOT&#95;CAUSE" |

## Scientific and integrity limitations

| Field | Value |
| --- | --- |
| "Oracle limitations" | &#91;"No generated candidate or real CVE is executed by this Oracle.", "Exit zero, crash, signal and Sanitizer messages alone never establish a specific CVE.", "Integrity hashes are not signatures or proof of a trustworthy collector/host.", "SYNTHETIC VERIFIED proves only offline rule behavior; real CVE remains NOT&#95;VERIFIED.", "Production root-cause assessors and affected/fixed differential standards are not implemented."&#93; |

Source documents support attributed claims, not execution facts.
Only bound, checked original artifacts can supply objective observations; Markdown and LLM prose cannot.
The local manifest detects byte changes relative to its recorded hashes; it is not a signature,
independent authentication, authorization, GPU isolation, or a claim that the local host is uncompromised.
