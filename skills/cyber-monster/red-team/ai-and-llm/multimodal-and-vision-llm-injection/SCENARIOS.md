# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`multimodal-and-vision-llm-injection`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: OCR Text Bypasses the Input Filter

- **Surface & Preconditions:** The input filter inspects uploaded bytes, and OCR runs afterwards.
- **Root Cause & Impact:** Instruction text rendered into an image reaches the model unfiltered and influences a tool call.
- **Verification & Fix:** Move the filter after extraction, label the extracted text as data, and test the same image again for the absence of the tool call.

## Case 2: PDF Text Layer Carries Hidden Instructions

- **Surface & Preconditions:** A PDF has visible content and a text layer with additional lines placed off-page.
- **Root Cause & Impact:** The extractor returns the hidden lines, which the model treats as part of the document.
- **Verification & Fix:** Compare extracted text with visible content, flag documents where they diverge, and treat the divergence as an injection attempt.
