# Research and artifact status

## Related publication

Sandeep Kalari, Sahithi Padidela, Vikas Ashok, and Ravi Mukkamala. **Exploring Large Language Models for Trustworthy Use: Insights from Research and Development.** ICISSP 2026, volume 2, pages 141–148. DOI: [10.5220/0014218400004061](https://doi.org/10.5220/0014218400004061).

The [ODU publication record](https://digitalcommons.odu.edu/computerscience_fac_pubs/452/) identifies PrivAware and BlockQwen as the systems discussed. This is a related systems-and-lessons publication, not evidence that this repository contains all experimental artifacts.

## What this snapshot supports

| Item | Status |
| --- | --- |
| Inference workflow | Source present |
| Role policies and FAISS indexing utility | Present |
| Authentication and database integration | Prototype source present; limitations remain |
| Fine-tuned checkpoint | Not included |
| Fine-tuning scripts | Not included |
| PPO/RLHF training or reward-model code | Not included |
| Evaluation dataset and scoring scripts | Not included |
| Reproduced benchmark results | Not established |

The previous README listed `3.91%` privacy leakage, a `15%` output-filtering baseline, and `90.13%` role-compliant accuracy. The checked-in files do not provide their dataset, metric definitions, evaluation scripts, or provenance. Those figures are retained here as unverified legacy claims rather than promoted as verified headline results.

Restoring a results table requires the primary experimental source, metric definitions, model/checkpoint identification, and evaluation setup. An available source excerpt does not substitute for the full experiment description.

## Questions for evaluation

- How much does each control contribute relative to generation alone?
- Which restricted requests are missed by subword-level masking?
- How often does sanitization remove allowed information or retain restricted information?
- Do database filters restrict both records and fields independently of model instructions?
- Can final placeholder substitution introduce information that was not checked earlier?
- How do utility, leakage, latency, and external-service cost change across roles?

These are evaluation questions, not reported outcomes of the current release.

[Back to PrivAware](../README.md)
