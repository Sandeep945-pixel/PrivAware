# Research papers and artifact status

## Primary methodology

**A Multi-Layered Privacy-Preserving Framework for Large Language Models in Healthcare**

**Authors:** Sahithi Padidela, Sandeep Kalari, Vikas G. Ashok, Ravi Mukkamala.

The author-supplied manuscript describes a Flan-T5-Large framework combining retrieved access policies, attention masking, response validation, database controls, and reinforcement learning from human feedback. Its Figure 2 is the research architecture and Figure 3 is the four-stage methodology included in this repository.

The supplied copy does not establish a final venue, DOI, or publication date. Citation metadata is therefore recorded as an author-supplied manuscript rather than inferred from its filename.

## Agentic extension

**PrivAgent-RL: Agentic Privacy Enforcement and Reward Modeling for Policy-Aware Fine-Tuning in Healthcare**

**Authors:** Sahithi Padidela, Sandeep Kalari, Vikas Ashok, Ravi Mukkamala.

This study extends layered privacy enforcement with a policy-aware evaluator agent. It separates response generation, reward assignment, and PPO refinement, replacing manual feedback with automated assessment. Figure 1 compares the feedback approaches; Figure 2 presents the agentic architecture.

The supplied copy carries an ACDSA 2026 heading. Final proceedings metadata and DOI have not been independently verified, so the citation identifies the supplied manuscript.

## Related overview publication

Sandeep Kalari, Sahithi Padidela, Vikas Ashok, and Ravi Mukkamala. **Exploring Large Language Models for Trustworthy Use: Insights from Research and Development.** ICISSP 2026, volume 2, pages 141–148. DOI: [10.5220/0014218400004061](https://doi.org/10.5220/0014218400004061).

The [ODU publication record](https://digitalcommons.odu.edu/computerscience_fac_pubs/452/) discusses PrivAware and BlockQwen. This overview is distinct from the two manuscripts above.

## Available artifacts

| Item | Status |
| --- | --- |
| PrivAware inference workflow | Source present |
| Role policies and FAISS indexing utility | Present |
| Authentication and database integration | Prototype source present; limitations remain |
| Research figures | Included for both studies |
| Fine-tuned checkpoint | Not included |
| Fine-tuning and PPO training code | Not included |
| PrivAgent-RL evaluator and reward pipeline | Not included |
| Evaluation datasets and scoring scripts | Not included |
| Independently reproduced results | Not established |

The source snapshot and research descriptions serve different purposes: the source shows the available implementation, while the manuscripts describe the broader methods and experiments. Reproduction requires the missing model and evaluation artifacts.

## Citation

[CITATION.bib](../CITATION.bib) contains separate entries for both manuscripts and the related overview, preserving each work's author order.

[Back to the project](../README.md)
