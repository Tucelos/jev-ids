# SOMIDS

Intrusion detection on NSL-KDD connection records with a System One Model (Jev),
compared with an LLM baseline and a Random Forest on data efficiency, cost and
latency.

## Language

### Data

**Flow**:
One NSL-KDD connection record: its 41 attributes and its label.
_Avoid_: row, line, record, connection.

**Category**:
The five-way label every Detector works with: `normal`, `dos`, `probe`, `r2l`,
`u2r`. Attack names such as `neptune` are never shown to a Detector.
_Avoid_: class, attack type (when the five-way label is meant).

**Novel attack**:
A Flow whose attack name occurs in KDDTest+ but never in KDDTrain+. Seventeen
such names exist.
_Avoid_: unseen attack, zero-day, new attack.

**Example**:
A labeled Flow drawn from KDDTrain+ and shown to a Detector as a reference,
labeled by Category only.
_Avoid_: shot, demonstration, training row.

**k**:
The number of Examples per Category given to a Detector. k = 0 is zero-shot;
k = 4 means twenty Examples.

**Split**:
A frozen, seeded sample of KDDTest+. `internal` is for tuning, `paper` for
reported results, `smoke` for exercising the pipeline; these three are
proportional. `hard` is a diagnostic sample, half attacks and half normals, of
Flows with low Difficulty. Splits are disjoint.

**Difficulty**:
NSL-KDD's per-record count of classic learners, out of 21, that classified the
record correctly. Low Difficulty means a hard Flow.
_Avoid_: subset, sample, test set.

### Detection

**Detector**:
Anything that turns a Flow plus Examples into a Prediction: Jev, an LLM
baseline or the Random Forest.
_Avoid_: model (reserved for a provider's model id), classifier, algorithm.

**Prediction**:
The output of one Detector for one Flow: Verdict, Category, p_attack,
confidence, and the tokens, cost and latency measured for it.
_Avoid_: record, result, answer.

**Verdict**:
The binary decision for a Flow, `attack` or `normal`, taken as p_attack ≥ 0.5
for every Detector.
_Avoid_: label, prediction (when only the binary decision is meant).

**p_attack**:
The probability that a Flow is an attack, as returned by the Detector: Jev's
`noul` answer, the number the LLM states, the Random Forest's class probability.
_Avoid_: score, confidence.

**confidence**:
Jev's per-question number for a `choice` question, derived from how spread out
the Category probabilities are. Only the Category question has one; `noul` has
none.
_Avoid_: certainty, probability.

**Batch (B)**:
The number of Flows judged in one Jev request over a shared state. The pilot
uses B = 1.

**Run**:
One execution of one Detector over one Split for a set of k values, seeds and
repetitions.
_Avoid_: experiment, job.

### Control loop

**Cascade**:
The three-zone control loop around Jev: block when p_attack ≥ τ_high, allow when
p_attack ≤ τ_low, escalate otherwise. Designed after the pilot.

**Escalation**:
Handing a Flow from the uncertain zone to the LLM agent for a second opinion.
