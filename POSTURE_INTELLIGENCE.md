# Security Posture Intelligence: Logic & Methodology

This document details the rigorous logic behind the scoring and verification engine of the platform.

## 1. Verification Statuses

The system uses a 5-state model for every security control:

| Status | Meaning | Score Impact |
|:---|:---|:---|
| **VERIFIED_PASS** | Technical evidence confirms the control is correctly implemented. | Neutral (Baseline 100) |
| **VERIFIED_FAIL** | Technical evidence (Findings) confirms a violation of the control. | High Penalty (-25 per control) |
| **SUSPECTED_ISSUE** | Inconclusive or low-confidence evidence suggests a potential failure. | Medium Penalty (-10 per control) |
| **INSUFFICIENT_EVIDENCE** | The control is applicable but tools could not confirm PASS or FAIL. | Slight Penalty (-5) or Neutral* |
| **NOT_APPLICABLE** | The control does not apply to this specific target type (e.g., API controls on a network target). | Neutral |

*\*Currently, Insufficient Evidence is treated as neutral in domain health to avoid "guessing", but it lowers the Verification Coverage score.*

## 2. Metric Formulas

### 2.1 Domain Health Score (0-100)
Calculated per WSTG domain (Configuration, Authentication, etc.).
- **Baseline**: 100 points.
- **Penalty**: `(FAIL_Count * 25) + (SUSPECTED_Count * 10)`.
- **Minimum**: 0.

### 2.2 Verification Coverage Score (%)
Measures the breadth of the assessment.
- **Formula**: `(Verified_Controls / Total_Applicable_Controls) * 100`
- *Verified Controls* = Any control with status `PASS` or `FAIL`.

### 2.3 Evidence Confidence Score (%)
Measures the reliability of the technical data.
- **Formula**: `(Sum of Finding_Confidence_Weights / Total_Findings) * 100`
- **Weights**: HIGH=1.0, MEDIUM=0.7, LOW=0.4.

### 2.4 Overall Posture Score (0-100)
The strategic aggregate.
- **Formula**: `(Average(Domain_Health_Scores) * 0.7) + (Coverage_Score * 0.2) + (Confidence_Score * 0.1)`
- This ensures that a scan with many "Inconclusive" results cannot achieve a high overall score even if no bugs are found.

## 3. Posture Grade (A-F)

Mapped directly from the **Overall Posture Score**:
- **A (90-100)**: Resilient. Strong controls, high coverage.
- **B (75-89)**: Secure. Good controls, minor gaps.
- **C (50-74)**: Exposed. Critical controls missing or low coverage.
- **D (30-49)**: Vulnerable. Significant failures and risks.
- **F (0-29)**: Critical Risk. Widespread failures.

## 4. Verification Rigor Guardrails

- **PASS Requirements**: A `PASS` status requires explicit positive evidence (e.g., specific headers found). Simply "no findings" results in `INSUFFICIENT_EVIDENCE`.
- **Deduplication**: Correlated findings count as a single failure for a control to avoid double-penalizing the same root cause.
- **N/A Handling**: Controls marked `NOT_APPLICABLE` are excluded from the denominator in Coverage and the average in Overall Score.
