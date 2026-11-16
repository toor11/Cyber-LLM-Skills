# AI and LLM

> Tree: `red-team/ai-and-llm` | **16 sub-skills** | Root router: [`../../SKILL.md`](../../SKILL.md)

**Weak-Model Rule:** Pick the **1 best matching** sub-skill below (`flagship` or `core` first unless a variant profile matches exactly), read its `SKILL.md`, and answer directly using its *Strict Output Contract*.

| Sub-skill | Tier | Focus & When to Use |
|---|---|---|
| [`llm-prompt-injection`](llm-prompt-injection/SKILL.md) | **flagship** | Tests and exploits prompt injection in LLM applications: direct and indirect injection, instruction override, tool-call hijacking, and data exfil |
| [`agentic-ai-and-mcp-security`](agentic-ai-and-mcp-security/SKILL.md) | **core** | Assesses agentic systems and tool protocols: tool permission scope, confused deputy paths, MCP server trust, and autonomous action chains |
| [`ai-application-assessment`](ai-application-assessment/SKILL.md) | **core** | Runs an end-to-end assessment of an AI application: data flow mapping, prompt surface review, output trust boundaries, tool permissions and monit |
| [`ai-guardrail-and-classifier-bypass`](ai-guardrail-and-classifier-bypass/SKILL.md) | **core** | Bypasses input and output classifiers and moderation layers: encoding and language switching, tokenisation boundaries, adversarial suffixes and p |
| [`llm-data-exfiltration-and-leakage`](llm-data-exfiltration-and-leakage/SKILL.md) | **core** | Extracts sensitive context from LLM applications: system prompt disclosure, training data memorisation, cross-tenant retrieval leakage and side-c |
| [`llm-jailbreak-and-guardrails`](llm-jailbreak-and-guardrails/SKILL.md) | **core** | Bypasses model guardrails and safety filters: role-play and encoding tricks, multi-turn escalation, refusal suppression and policy boundary probi |
| [`llm-output-handling-and-sinks`](llm-output-handling-and-sinks/SKILL.md) | **core** | Exploits unsafe handling of model output: markdown and HTML injection into rendered chat, generated code executed downstream, model output used i |
| [`mitre-atlas-ml-threat-coverage`](mitre-atlas-ml-threat-coverage/SKILL.md) | **core** | Maps and assesses machine-learning systems against MITRE ATLAS tactics: ML supply-chain compromise, training/fine-tuning poisoning, membership in |
| [`rag-and-vector-store-attacks`](rag-and-vector-store-attacks/SKILL.md) | **core** | Attacks retrieval augmented generation: poisoning the vector store, embedding inversion, chunk boundary injection and retrieval ranking manipulat |
| [`ai-assisted-offensive-tooling`](ai-assisted-offensive-tooling/SKILL.md) | **leaf** | Uses AI assistants deliberately in offensive work: payload variation, reconnaissance summarisation, code generation and triage, with verification |
| [`ai-supply-chain-and-plugin-risk`](ai-supply-chain-and-plugin-risk/SKILL.md) | **leaf** | Assesses plugin, extension and tool-integration risk in AI systems: third-party tool trust, credential delegation to plugins and prompt-injectabl |
| [`fine-tuning-and-lora-alignment-security`](fine-tuning-and-lora-alignment-security/SKILL.md) | **leaf** | Assesses security risks in custom fine-tuning, LoRA/QLoRA adapters, and RLHF datasets: safety-alignment degradation from small poisoned subsets, |
| [`llm-denial-of-service-and-cost`](llm-denial-of-service-and-cost/SKILL.md) | **leaf** | Assesses resource and cost exhaustion in LLM systems: unbounded context growth, recursive tool loops, expensive prompt amplification and rate-lim |
| [`ml-adversarial-and-data-poisoning`](ml-adversarial-and-data-poisoning/SKILL.md) | **leaf** | Attacks ML systems at the model level: adversarial examples, training data poisoning, backdoors and model extraction |
| [`model-and-artifact-supply-chain`](model-and-artifact-supply-chain/SKILL.md) | **leaf** | Assesses model and artifact supply chains: untrusted model sources, pickle and serializer risk in weights, unsafe model hubs and dependency prove |
| [`multimodal-and-vision-llm-injection`](multimodal-and-vision-llm-injection/SKILL.md) | **leaf** | Tests multimodal vision/audio LLMs for cross-modal indirect prompt injection: OCR/steganographic instructions embedded in images, PDFs, screensho |
