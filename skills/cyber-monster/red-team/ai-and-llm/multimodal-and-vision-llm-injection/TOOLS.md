# Tools, CLI Flags, and SDK Reference

> Sub-skill: [`multimodal-and-vision-llm-injection`](SKILL.md) | Family: **AI and LLM**

Flags below are the ones that matter for this technique, not an exhaustive dump. Re-check with `--help` against the installed version before quoting a flag.

## Pinned Engineering Stack

- **Primary SDK / Schema:** an extraction step per modality (OCR, PDF text layer, audio transcription), filtering applied to the extracted text, and metadata inspection.
- **Validation Gate:** one document with embedded text where the extractor output is compared with the visible content.
- Filtering must run on the extracted text; a byte-level check on the upload misses everything the model reads.

## Tool and Command Matrix

| Tool / Package | Verified Command or Entry Point | Purpose | Platforms |
|---|---|---|---|
| `pdftotext` | `pdftotext document.pdf -` | Extract the PDF text layer for comparison with the visible page | Cross-platform |
| `exiftool` | `exiftool -a -G1 image.png` | Inspect metadata channels in an image | Cross-platform |
| `python` | `python -c "import json; print(json.load(open('pipeline.json'))['stages'])"` | Read the pipeline stage order | Cross-platform |

## Minimal Script Shape

Smallest shape that matches the current API and stays read-only by default.

```python
import json

stages = json.load(open("pipeline.json", encoding="utf-8"))["stages"]
names = [s["name"] for s in stages]
print(names)
print("filter covers extraction" if names.index("filter") > names.index("extract") else "FILTER BEFORE EXTRACT")
```
