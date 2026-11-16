# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`static-pe-elf-apk-feature-extractor-scripting`](SKILL.md) | Family: **Security Automation and Tool Development**

Representative static-extraction failures, each with the artifact that proves the diagnosis.

## Case 1: A malformed sample killed the batch

- **Surface & Preconditions:** an extractor runs over a corpus of a few thousand samples and one has a truncated section table.
- **Root cause & impact:** the exception propagates out of the loop and the run stops at sample 412. The remaining corpus is never analysed, and the coverage report says the pipeline ran.
- **Verification & fix:** catch parser exceptions per sample, record the sample hash and error, continue, and report the count of unparsed samples at the end.

## Case 2: The model's features changed without the model changing

- **Surface & Preconditions:** a parser library is upgraded in the base image, and the feature extractor is untouched.
- **Root cause & impact:** field semantics and defaults shift between versions, so the same samples now produce different vectors. Classifier performance changes for reasons nobody can see in the model repository.
- **Verification & fix:** pin parser versions, record the version in every record, and fail CI when a pinned version changes without a corresponding feature-schema review.

## Case 3: Declared size read literally

- **Surface & Preconditions:** a packed sample declares a section `SizeOfRawData` far larger than the file.
- **Root cause & impact:** `get_data()` attempts the read and the process consumes memory or raises in an unexpected place. A crafted header becomes a denial of service against the analysis pipeline.
- **Verification & fix:** compare declared sizes against the file length and a hard cap, skip and record oversized structures.

## Case 4: High entropy declared malicious

- **Surface & Preconditions:** a rule treats section entropy above 7.0 as a malicious indicator.
- **Root cause & impact:** compressed legitimate installers, updaters, and several commercial packers all exceed that threshold, so benign software is flagged at scale and the signal is abandoned.
- **Verification & fix:** treat entropy as one feature among several (imports, signature presence, section permissions) and never as a verdict.
