# Verified references: agentic context engineering and its security

Fact report, checked 2026-09-23. Every citation was verified against the paper, the standard, or the
maintainer's own release data — not against secondary summaries.

---

## 1. Agentic Context Engineering (ACE) — the "delta update" / "context collapse" paper

**The paper exists, essentially as remembered.**

> Zhang, Q., Hu, C., Upasani, S., Ma, B., Hong, F., Kamanuru, V., Rainton, J., Wu, C., Ji, M.,
> Li, H., Thakker, U., Zou, J., & Olukotun, K. (2026). *Agentic Context Engineering: Evolving
> Contexts for Self-Improving Language Models.* International Conference on Learning
> Representations (ICLR 2026). arXiv:2510.04618. <https://arxiv.org/abs/2510.04618>

- arXiv metadata: v1 submitted 2025-10-06, v3 updated 2026-03-29, comment field reads
  `ICLR 2026; 32 pages`. Affiliations on the title page: SambaNova Systems, Stanford University,
  UC Berkeley.
- Context collapse, verbatim: "As the context grows large, the model tends to compress it into
  much shorter, less informative summaries, causing a dramatic loss of information." The paper shows
  a context collapsing from 18,282 tokens (66.7% accuracy) to 122 tokens (57.1%) in a single step.
- Delta updates, verbatim: "Rather than regenerating contexts in full, ACE incrementally produces
  compact delta contexts: small sets of candidate bullets distilled by the Reflector and integrated
  by the Curator."
- ACE's three roles are Generator / Reflector / **Curator** — the same word this project uses for its
  agent; worth flagging in the report as deliberate alignment.

**Relevance:** the direct methodological antecedent for an agent that edits a context playbook
between rounds, and the source of the named failure mode (context collapse) that wholesale rewriting
causes. **Verified from primary source: yes** (arXiv API metadata + arXiv HTML full text).
*Caveat:* cite as ICLR 2026, not "2025" — the 2025 date is the preprint only.

---

## 2. AgentPoison

**Verified exactly as remembered.**

> Chen, Z., Xiang, Z., Xiao, C., Song, D., & Li, B. (2024). *AgentPoison: Red-teaming LLM Agents via
> Poisoning Memory or Knowledge Bases.* Advances in Neural Information Processing Systems 37
> (NeurIPS 2024). arXiv:2407.12784. <https://arxiv.org/abs/2407.12784>
> Proceedings PDF: <https://proceedings.neurips.cc/paper_files/paper/2024/file/eb113910e9c3f6242541c1652e30dfd6-Paper-Conference.pdf>

arXiv: submitted 2024-07-17, v1 only, 22 pages; NeurIPS 2024 poster
(<https://neurips.cc/virtual/2024/poster/94715>). Reports ≥80% attack success at <0.1% poison rate
with ≤1% degradation on benign inputs.

**Relevance:** the canonical demonstration that an agent's *retrieved* state is an attack surface
reachable without retraining — the threat model this project's poisoned feedback channel
instantiates.

**Verified from primary source: yes** (arXiv metadata + NeurIPS proceedings).

---

## 3. OWASP Top 10 for LLM Applications

Current edition is **2025**, maintained by the **OWASP Gen AI Security Project**.
List page: <https://genai.owasp.org/llm-top-10/> ·
Document/PDF page: <https://genai.owasp.org/resource/owasp-top-10-for-llm-applications-2025/>

The two entries requested, with exact published codes and titles:

- **LLM04:2025 Data and Model Poisoning** —
  <https://genai.owasp.org/llmrisk/llm042025-data-and-model-poisoning/>
  Manipulation of pre-training, fine-tuning **and embedding** data to introduce backdoors, bias or
  degraded behaviour.
- **LLM09:2025 Misinformation** —
  <https://genai.owasp.org/llmrisk/llm092025-misinformation/>
  Credible-sounding false output; the entry explicitly folds in overreliance: "Overreliance occurs
  when users place excessive trust in LLM-generated content, failing to verify its accuracy."

Do not reuse older numbering: in 2025 "Training Data Poisoning" became LLM04 and absorbed model
poisoning, and the former "Overreliance" category was renamed **Misinformation** at LLM09.

**Relevance:** LLM04 names the adversary's action (poisoning what the curator learns from); LLM09
names the consequence (a detector that confidently reports the wrong thing and is believed).

**Verified from primary source: yes** (owasp.org and genai.owasp.org pages).
*Date caveat:* the resource page dates the 2025 edition **17 November 2024**; the "March 12, 2025"
and "July 22, 2025" dates on the list page belong to translations. Prefer "2025 edition".

---

## 4. MITRE ATLAS

> MITRE. *ATLAS — Adversarial Threat Landscape for AI Systems.* <https://atlas.mitre.org/>
> Technique: **AML.T0020 — Training Data Poisoning**, tactic **Persistence**.
> <https://atlas.mitre.org/techniques/AML.T0020>

A living, globally accessible knowledge base of adversary tactics and techniques against AI systems,
built from real-world attacks and red-team demonstrations. Current release **v2026.09** (16 tactics,
208 techniques). AML.T0020: created 2021-05-13, last modified 2026-07-31; platforms Predictive,
Generative and **Agentic AI**. Description verbatim — note the final clause, which covers this
project's threat model directly:

> "Adversaries may manipulate data used for training or fine-tuning an AI model to influence the
> resulting model's behavior. Adversaries may add, remove, or modify data samples; **alter labels or
> annotations; or manipulate feedback and data-collection processes.**"

Two corrections and one bonus:

- Titled **"Poison Training Data"** up to ATLAS v5.6.0, **now "Training Data Poisoning"**. Many
  third-party pages still show the old title; use the new one.
- An even closer technique exists: **AML.T0080 — AI Agent Context Poisoning** (Persistence), with
  sub-techniques **AML.T0080.000 Memory** and **AML.T0080.001 Thread**.
  <https://atlas.mitre.org/techniques/AML.T0080>
- Case study **AML.CS0009 Tay Poisoning** is a real-world feedback-loop poisoning incident — a good
  one-line motivator.

**Verified from primary source: yes** — via MITRE's own release data
(`dist/v6/ATLAS-2026.09.yaml` in <https://github.com/mitre-atlas/atlas-data>) and by in-browser
navigation of atlas.mitre.org. Deep links to `/techniques/...` return HTTP 404 to plain HTTP clients
because the site is a client-routed SPA; the URLs above are the site's own canonical hrefs and do
resolve in a browser.

---

## 5. Additional primary sources

**(a) Self-improvement from feedback**

> Shinn, N., Cassano, F., Berman, E., Gopinath, A., Narasimhan, K., & Yao, S. (2023). *Reflexion:
> Language Agents with Verbal Reinforcement Learning.* Advances in Neural Information Processing
> Systems 36 (NeurIPS 2023), pp. 8634–8652. arXiv:2303.11366. <https://arxiv.org/abs/2303.11366>

Relevance: the canonical formulation of an agent that turns task feedback into natural-language
self-reflection held in memory — precisely the loop this project's adversary attacks.
**Verified from primary source: yes.** *Caveat:* the NeurIPS page lists five authors (omitting
E. Berman); arXiv v4 lists six. Follow whichever version you cite.

**(b) Poisoning the human-feedback channel**

> Rando, J., & Tramèr, F. (2024). *Universal Jailbreak Backdoors from Poisoned Human Feedback.*
> International Conference on Learning Representations (ICLR 2024). arXiv:2311.14455.
> <https://arxiv.org/abs/2311.14455>

Relevance: the closest published analogue to this project's adversary — control of a small fraction
of the *feedback/annotation* stream implants a trigger that survives training.
**Verified from primary source: yes** (arXiv comment: "Accepted as conference paper in ICLR 2024").
The title contains no "RLHF poisoning" phrase; cite it exactly as above.

**(c) Poisoning and defence in the learning loop**

> Jagielski, M., Oprea, A., Biggio, B., Liu, C., Nita-Rotaru, C., & Li, B. (2018). *Manipulating
> Machine Learning: Poisoning Attacks and Countermeasures for Regression Learning.* 39th IEEE
> Symposium on Security and Privacy (S&P 2018). arXiv:1804.00308.
> <https://arxiv.org/abs/1804.00308>

Relevance: optimisation-based poisoning plus the TRIM trimmed-loss defence — the standard reference
for how far a bounded fraction of corrupted training signal can move a model, and which robust
estimator resists it. **Verified from primary source: yes** (arXiv metadata; venue stated in the
authors' own comment field).

Also real and available if a fourth is wanted, but arXiv-only with no venue:
Wang, Y., & Chaudhuri, K. (2018). *Data Poisoning Attacks against Online Learning.* arXiv:1808.08994.

---

## Could NOT verify — do not cite as stated

- **"Zhang et al., 2025"** as a venue-bearing citation for ACE. 2025 is the preprint; the
  peer-reviewed version is **ICLR 2026**.
- **"Poison Training Data (AML.T0020)"** — the old ATLAS title, superseded by *Training Data
  Poisoning*. Still widely repeated on third-party sites.
- **A specific English release date for the OWASP 2025 edition.** Cite the edition, not a day.
- **OWASP 2023-edition entry codes** ("LLM03:2023", "LLM09:2023", etc.). Not checked; do not assert.
- **Any venue for AgentPoison other than NeurIPS 2024.** No journal version, no arXiv v2.
