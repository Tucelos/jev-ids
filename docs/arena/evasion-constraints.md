# Realism constraints for adversarial perturbation of NSL-KDD flow records

Fact report for the r2l/dos evasion study. Claims that are my own reasoning rather than a cited
paper's are marked **[synthesis]**.

---

## 1. Problem space vs. feature space, and the four constraints

A **feature-space** attack edits the vector the classifier consumes; a **problem-space** attack must
produce a real object whose feature mapping lands where the attacker wants. Because that mapping is
generally neither invertible nor differentiable, "the adversary must perform a search in the
problem-space that approximately follows the negative gradient in the feature space" ([Pierazzi,
Pendlebury, Cortellazzi, Cavallaro,
*Intriguing Properties of Adversarial ML Attacks in the Problem Space*, IEEE S&P 2020,
pp. 1332–1349](https://fabio.pierazzi.com/assets/pdf/pierazzi_intriguing.pdf); extended version
[Cortellazzi et al., ACM TOPS 28(4), 2025](https://dl.acm.org/doi/10.1145/3742895),
[arXiv:1911.02142](https://arxiv.org/abs/1911.02142)).

**Correction to the brief:** the paper defines **four constraints** plus a *separate* concept of
side-effect features. Side-effect features are not one of the four. Verbatim:

1. **Available transformations** (Def. 8) — "which modifications can be performed in the
   problem-space by the attacker (e.g., only addition and not removal)."
2. **Preserved semantics** (Def. 9) — "the semantics to be preserved while mutating z to z′, with
   respect to specific feature abstractions which the attacker aims to be resilient against."
   Semantic equivalence being undecidable, it is approximated by *automated tests*.
3. **Plausibility (or Inconspicuousness)** (Def. 10) — "which (qualitative) properties must be
   preserved ... so that z′ appears realistic upon manual inspection," verified by *typically manual*
   tests.
4. **Robustness to preprocessing** (Def. 11) — "which non-ML techniques could disrupt the attack
   (e.g., filtering in images, dead code removal in programs)."

Def. 12 bundles these: they **determine** the feature-space constraints and are a **superset** of
them — some "may not be possible to enforce in the feature space." (The S&P 2020 abstract calls the
fourth "absent artifacts".)

**Side-effect features** (Def. 13) are "the features that are altered in z′ = T(z) specifically for
the satisfaction of problem-space constraints," and crucially "do not follow any particular direction
of the gradient." The paper frames this as a **projection** of a feature-space attack vector back
onto the feasible problem-space region — the key idea for our attacker (§4).

---

## 2. Apruzzese et al. on realistic attacks against NIDS

**Threat model.** [Apruzzese, Andreolini, Ferretti, Marchetti, Colajanni, *Modeling Realistic
Adversarial Attacks against Network Intrusion Detection Systems*, ACM DTRAP 3(3), art. 31, 2022,
DOI 10.1145/3469659](https://dl.acm.org/doi/10.1145/3469659),
[arXiv:2106.09380](https://arxiv.org/abs/2106.09380) decomposes attacker *power* into five elements:
**training data** (read/write/none), **feature set**, **detection model** (each none/partial/full),
**oracle** (feedback from NIDS output), and **manipulation depth** (problem vs. feature space).

Their central claim for us: **feature-space attacks are not a realistic NIDS threat model.** "The
only way in which an adversary could perform a real feature-space attack is by manipulating the
conversion of the raw traffic data into its feature representation, which requires full power on the
ML component." The attacker cannot write feature values, because "the actual features representing
each sample and used to perform the detection are specified only at inference time" — the *defender*
computes them. Full model knowledge is likewise dismissed: the model "is deployed on machines whose
access requires high administrative privileges." On **cost**, oracle power needs operations spanning
"an extended amount of time, up to days or weeks," which "increase the probability that the attacker
is detected"; and "some network flow collectors have fixed thresholds for the maximum flow duration."

**Which features they treat as controllable.** [Apruzzese, Andreolini, Colajanni, Marchetti,
*Hardening Random Forest Cyber Detectors Against Adversarial Attacks*, IEEE TETCI 4(4), 2020,
pp. 427–439](https://arxiv.org/abs/1912.03790) perturbs exactly four NetFlow features — `duration`,
`src_bytes`, `dst_bytes`, `tot_pkts`: "An attacker can evade detection by increasing the flow
duration through a small latency; and the number of bytes (or packets) by adding random junk data ...
without altering their underlying logic." Perturbations are therefore **monotone increases only** and
**bounded** — "excessive increases ... may generate anomalous network flows." Scope condition: in
this *botnet* setting both endpoints are attacker-controlled, which is why `dst_bytes` counts as
controllable; that does not transfer to r2l against a third-party victim. **[synthesis]**

**Cost-driven threat modelling.** [Apruzzese, Anderson, Dambra, Freeman, Pierazzi, Roundy, *"Real
Attackers Don't Compute Gradients"*, IEEE SaTML 2023, pp. 339–364](https://arxiv.org/abs/2212.14315):
"Economics is the main driver of practical cybersecurity—both for attackers and defenders." Observed
evasion uses "relatively simple, yet often effective, strategies ... unlikely to result from gradient
computations." **27% of reviewed papers never mention cost**; of the 57% that do, most "overlook the
human cost factor."

Not verified: the perturbed-feature list of the DRAL paper (Apruzzese et al., IEEE TNSM 17(4), 2020,
DOI 10.1109/TNSM.2020.3031843) — paywalled, no preprint found.

---

## 3. IDSGAN's functional-feature partition, verified

[Lin, Shi, Xue, *IDSGAN: Generative Adversarial Networks for Attack Generation against Intrusion
Detection*, PAKDD 2022, arXiv:1809.02077](https://arxiv.org/abs/1809.02077) splits the 41 features
into "intrinsic", "content", "time-based traffic", "host-based traffic", and defines a **restricted
modification mechanism**: "the functional features of each attack should be kept unchanged to
preserve malicious functionalities. The mechanism allows the fine-tuning or retention of
nonfunctional features."

**Their Table 1, recovered exactly** by glyph-coordinate analysis of the PDF (the check marks are
AMS-font glyphs that text extraction drops). At least one HTML rendering of this paper reproduces
the table **incorrectly** — verify before citing.

| Attack | Intrinsic | Content | Time-based traffic | Host-based traffic |
|---|:---:|:---:|:---:|:---:|
| Probe | ✓ | | ✓ | ✓ |
| DoS   | ✓ | | ✓ | |
| U2R   | ✓ | ✓ | | |
| R2L   | ✓ | ✓ | | |

So **for r2l, IDSGAN freezes intrinsic + content and frees all 19 time-based and host-based features;
for dos it freezes intrinsic + time-based and frees the 13 content and 10 host-based features.** They
add: "Concerning that 'intrinsic' features are the functional features in all the attacks of NSL-KDD,
the nonnumeric features will not be modified."

**Caveat:** IDSGAN never enumerates which of the 41 named features belongs to which group; that
mapping comes from the KDD Cup 99 task description. Anyone reproducing the partition imports an
assumption. **[synthesis]**

### Critiques

- **The implementation breaks its own constraint.** [Alatwi & Morisset, *Adversarial Machine Learning
  In Network Intrusion Detection Domain: A Systematic Review*, arXiv:2112.03315,
  2021](https://arxiv.org/abs/2112.03315): "Although preserving the network traffic's functional
  features was claimed, two functional features were altered which invalidate maintaining functional
  properties of adversarial traffic." Also: "the majority of studies did not take into consideration
  the domain constraints on NIDS features."
- **Group granularity is too coarse.** [Vitorino, Praça, Maia, *SoK: Realistic Adversarial Attacks and
  Defenses for Intelligent Network Intrusion Detection*, Computers & Security,
  2023](https://doi.org/10.1016/j.cose.2023.103433) require **validity** ("compliance with the
  constraints of a domain") and **coherence** ("compliance with the constraints of a specific class").
  Their Table 3 marks IDS-GAN ✗ for constraint support: "a feature may also be highly correlated to
  several others, being required to exhibit specific values depending on the other characteristics of
  a sample."
- **Protocol constraints ignored.** [Sheatsley, Papernot, Weisman, Verma, McDaniel, *Adversarial
  Examples in Constrained Domains*, arXiv:2011.01183, 2020](https://arxiv.org/abs/2011.01183) learn
  NSL-KDD constraints with transport protocol as primary feature: TCP admits 112 associated feature
  values vs. 27 for UDP and 29 for ICMP. Their failure case: an unconstrained attack "suggests that
  the current service, `tftp_u`, should be switched to `ftp`, which is a service constrained to TCP."
- **My objection, specific to r2l. [synthesis]** IDSGAN's r2l partition is close to *inverted* with
  respect to problem-space realizability: it correctly freezes content (which the r2l payload
  determines) but frees exactly the 19 features the attacker can *least* directly set, since the
  sensor recomputes them from surrounding traffic (§4). For dos it frees the content block, which is
  identically zero in real dos flows — writing non-zero values there asserts application-layer
  activity that never happened, violating *plausibility* and arguably *preserved semantics*.

---

## 4. Why the 19 derived features cannot be set independently

**Primary-source definitions.** The [KDD Cup 1999 task
description](https://kdd.ics.uci.edu/databases/kddcup99/task.html) states that "same host" features
"examine only the connections in the past two seconds that have the same destination host as the
current connection," and "same service" features likewise over "the same service as the current
connection." The framework originates with [Lee & Stolfo, *A Framework for Constructing Features and
Models for Intrusion Detection Systems*, ACM TISSEC 3(4), 2000,
pp. 227–261](https://dl.acm.org/doi/10.1145/382912.382914).

The host-based block exists **precisely to defeat an attacker who slows down**. Verbatim: "Some
probing attacks scan the hosts (or ports) using a much larger time interval than two seconds, for
example once per minute. Therefore, connection records were also sorted by destination host, and
features were constructed using a window of 100 connections to the same host instead of a time
window. This yields a set of so-called host-based traffic features."

Combined with Apruzzese (§2), the reviewer-proof argument is: these 19 values are *functions of the
attacker's connection log*, not fields the attacker writes.

**The correct causal model. [synthesis]** Parameterise the attacker's *behaviour* — inter-connection
interval `λ`, target hosts `H`, services/ports `S`, source-port reuse — then **replay the connection
log and recompute** all 19 derived features. Never edit them independently.

- **Slowing down (larger `λ`)**: `count` and `srv_count` fall monotonically, being raw counts in a
  *fixed 2 s* window. The six rate features are *ratios*, so they do **not** fall with rate — the
  attacker's connections become a smaller share of the window and the ratios are **diluted toward the
  ambient background mix** (`same_srv_rate` ↓, `diff_srv_rate` ↑, `serror_rate`/`rerror_rate` drift
  toward background). Critically, the ten `dst_host_*` features are **near-invariant to slowing
  down**, their window being 100 connections rather than a time span — exactly the rationale quoted
  above.
- **Spreading across hosts (larger `H`)**: `count` ↓; `srv_count` roughly unchanged if the same
  service is targeted everywhere; `srv_diff_host_rate` ↑; per-target `dst_host_count` and
  `dst_host_srv_count` ↓; `dst_host_srv_diff_host_rate` ↑.
- **Spreading across services/ports (larger `S`)**: `same_srv_rate` ↓ / `diff_srv_rate` ↑;
  `dst_host_same_srv_rate` ↓ / `dst_host_diff_srv_rate` ↑; `dst_host_same_src_port_rate` ↓ under
  source-port randomisation.

**Hard couplings. [synthesis, implied by the definitions above]**
`same_srv_rate + diff_srv_rate ≈ 1` and `dst_host_same_srv_rate + dst_host_diff_srv_rate ≈ 1` (same
window, partitioned); `dst_host_srv_count ≤ dst_host_count`;
`dst_host_same_srv_rate ≈ dst_host_srv_count / dst_host_count`; the `*serror_rate` family is tied to
`flag`. Not empirically validated against the CSVs — do that first.

These forced co-movements *are* Pierazzi's **side-effect features**: the corrections incurred by
projecting a desired feature-space move back into the feasible problem space.

---

## 5. NSL-KDD as a benchmark: limitations to acknowledge

[Tavallaee, Bagheri, Lu, Ghorbani, *A Detailed Analysis of the KDD CUP 99 Data Set*, IEEE CISDA 2009,
pp. 1–6, DOI 10.1109/CISDA.2009.5356528](https://www.ee.torontomu.ca/~bagheri/papers/cisda.pdf):
"about 78% and 75% of the records are duplicated in the train and test set, respectively"
(4,898,431 → 1,074,992 distinct train records, 78.05%; 311,027 → 77,289 distinct test, 75.15%), which
"will cause the classifiers to be biased towards the frequent records."

The same authors state NSL-KDD's own limits: "the proposed data set still suffers from some of the
problems discussed by McHugh and may not be a perfect representative of existing real networks" —
justified only "because of the lack of public data sets for network-based IDSs." The referenced
critique is [McHugh, *Testing Intrusion Detection Systems*, ACM TISSEC 3(4), 2000,
pp. 262–294](https://dl.acm.org/doi/10.1145/382912.382923).

Recent: [Goldschmidt & Chudá, *Network Intrusion Datasets: A Survey, Limitations, and
Recommendations*, Computers & Security, 2025, arXiv:2502.06688](https://arxiv.org/abs/2502.06688) say
KDD'99 and NSL-KDD have been criticised for "questionable data validity, the existence of artifacts,
lack of real-world attack stealthiness, or inconsistencies between DARPA 1998 data and KDD'99
features indicating labeling issues," and conclude they "are no longer recommended for IDS
benchmarking" — while noting "many recent studies still rely on them."

**Framing suggestion. [synthesis]** Do not defend NSL-KDD as realistic traffic; defend it as a
*constraint-modelling testbed* whose 41 features have publicly documented derivation semantics. The
contribution is the constraint model, not the absolute detection numbers.

---

## Proposed feature partition for r2l and dos

Column 2: **direct** = attacker sets it by choosing its own behaviour; **derived** =
derived-follows-behaviour, recomputed by the sensor from the connection log; **fixed** =
fixed-by-attack-semantics. Where r2l and dos differ, both are given.

| Feature | Attacker-controllable? | Justification (citation) |
|---|---|---|
| `duration` | direct (increase-only, bounded) | "increasing the flow duration through a small latency"; collector caps flow duration (Apruzzese, TETCI 2020). **Contradicts** IDSGAN, which freezes all intrinsic features. **[synthesis of the conflict]** |
| `protocol_type` | fixed | Primary constraint feature determining admissible services/flags (Sheatsley et al. 2020); also frozen by IDSGAN as non-numeric. |
| `service` | fixed | Constrained by protocol; switching yields infeasible flows (Sheatsley et al. 2020). r2l classes are service-defined (guess_passwd→telnet/ftp, phf→http, imap→imap4). **[synthesis for the per-class mapping]** |
| `flag` | derived / fixed | TCP termination status — an outcome, not an input. For dos `neptune`, `flag=S0` is definitional. **[synthesis]** |
| `src_bytes` | direct (increase-only) | "adding random junk data" without altering underlying logic (Apruzzese, TETCI 2020). |
| `dst_bytes` | r2l: derived (victim-determined); dos: direct in botnet settings | Apruzzese perturbs it only because both endpoints are bots; an r2l victim server controls its own response. **[synthesis of the scope condition]** |
| `land` | fixed | Definitional invariant (src host/port = dst host/port); KDD task description. |
| `wrong_fragment` | fixed | Definitional for fragmentation dos (teardrop); 0 for r2l. **[synthesis]** |
| `urgent` | direct but implausible | Settable via URG pointer, but non-zero values are conspicuous — Pierazzi plausibility constraint. **[synthesis]** |
| `hot`, `num_failed_logins`, `logged_in`, `num_compromised`, `root_shell`, `su_attempted`, `num_root`, `num_file_creations`, `num_shells`, `num_access_files`, `is_host_login`, `is_guest_login` | r2l: **fixed**; dos: **fixed at 0** | IDSGAN Table 1 marks content functional for R2L (verified). `num_failed_logins` *is* the guess_passwd signal; `is_guest_login`/`num_file_creations` are definitional for warezmaster/ftp_write. For dos IDSGAN calls them modifiable, but real dos flows have them identically 0 — writing non-zero violates plausibility (Pierazzi et al. 2020). **[synthesis for dos]** |
| `num_outbound_cmds` | fixed (degenerate) | Constant 0 throughout NSL-KDD; carries no information. Verify in your own load. **[synthesis, not verified against a paper]** |
| `count`, `srv_count` | derived | Raw counts over a fixed 2 s window (KDD task description); fall monotonically as the attacker slows. **[synthesis for the direction]** |
| `serror_rate`, `srv_serror_rate`, `rerror_rate`, `srv_rerror_rate` | derived | Ratios over the 2 s window (KDD task description); diluted toward background rates as the attacker slows, not reduced. Coupled to `flag`. **[synthesis for the direction]** |
| `same_srv_rate`, `diff_srv_rate` | derived, mutually coupled | Partition the same-host 2 s window, so they sum to ≈1 (KDD task description). Move only via service spread. **[synthesis for the identity]** |
| `srv_diff_host_rate` | derived | % of same-service connections to different hosts; rises with host spread (KDD task description). **[synthesis for the direction]** |
| `dst_host_count`, `dst_host_srv_count` | derived; **invariant to slowing down** | Window is "100 connections to the same host instead of a time window," introduced specifically to catch slow scans (KDD task description). `dst_host_srv_count ≤ dst_host_count`. **[synthesis for the ordering]** |
| `dst_host_same_srv_rate`, `dst_host_diff_srv_rate` | derived, mutually coupled | Sum to ≈1 over the 100-connection window; `dst_host_same_srv_rate ≈ dst_host_srv_count / dst_host_count`. **[synthesis]** |
| `dst_host_same_src_port_rate` | derived | Falls under source-port randomisation (KDD task description). **[synthesis for the direction]** |
| `dst_host_srv_diff_host_rate` | derived | Rises with host spread (KDD task description). **[synthesis for the direction]** |
| `dst_host_serror_rate`, `dst_host_srv_serror_rate`, `dst_host_rerror_rate`, `dst_host_srv_rerror_rate` | derived | Error ratios over the 100-connection window; follow from connection outcomes, coupled to `flag` (KDD task description). **[synthesis for the coupling]** |

**Net effect.** For r2l the attacker has three genuinely direct levers (`duration`, `src_bytes`, and
the behaviour parameters `λ`/`H`/`S`), nine fixed intrinsic-ish fields, twelve fixed content fields,
and nineteen derived fields reachable only as a joint consequence of behaviour. For dos,
`count`/`srv_count` and the time-based rates become **fixed** (high rate *is* the attack), leaving
only `duration`, byte padding, and host/port spread.

---

## Open questions / what I could not verify

1. **DRAL feature list** — perturbed features/ranges in Apruzzese et al., IEEE TNSM 17(4), 2020.
   Paywalled, no preprint. Do not cite specifics.
2. **Which two features IDSGAN actually altered** — Alatwi & Morisset assert it but do not name them;
   not traced to IDSGAN's released code.
3. **Greek notation in Pierazzi et al.** — stripped by PDF text extraction. Definitions verified by
   name and content, not the exact glyphs; check the PDF before reproducing notation.
4. **Coupling identities not empirically validated** (`same_srv_rate + diff_srv_rate = 1`,
   `dst_host_srv_count ≤ dst_host_count`, `num_outbound_cmds ≡ 0`). They follow from the published
   definitions, but rounding/truncation in the original derivation may break exact equality.
5. **No paper found that partitions NSL-KDD features for r2l on causal grounds.** Those rows are my
   synthesis from KDD derivation semantics plus the Pierazzi/Apruzzese framework.
6. **IDSGAN venue** — arXiv 1809.02077 (2018), published PAKDD 2022; confirm pagination.
