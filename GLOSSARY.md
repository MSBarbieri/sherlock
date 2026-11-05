# Sherlock

Language for reviewing possible secrets in repository history.

## Language

**Finding**:
A potential secret at a particular location in repository history, supported by one or more scanner reports.

**Scanner report**:
A scanner's evidence that a location may contain a secret. Multiple reports can support the same finding.

**False positive**:
A developer's decision that a finding does not represent a secret requiring remediation.

**Accepted risk**:
A developer's decision to acknowledge a finding without remediating it at that time.
