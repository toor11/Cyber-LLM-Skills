# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`type-juggling-javascript-other-languages`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Magic Test

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-843`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Magic test (Web) In the task we get a very simple webpage where we can input a name and birthday. We get source code of the server part as well: 'javascript const express = require('express') const app = express() function getTimestamp(date) { try{ var x = Math.floor((new Dat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: quotes

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-843`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** The challenge provided the URL for the web app and its source code. When I accessed the URL, the web app displayed this message: The source code contained these files: After checking where the flag should be, I noticed it is the 8th quote in the 'quotes' file. Let's check 'app.js
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: slots

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-843`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** ' $ nc [web.angstromctf.com] (http://web.angstromctf.com) 3002 Welcome to Fruit Slots! We've given you $10.00 on the house. Once you're a high roller, we'll give you a flag. You have $10.00. Enter your bet: NaN ? : ? : ? ? : ? : ? ◀ ? : ? : ? You lost everything. Wow, you're a h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Segfault if 'tf.histogram_fixed_width' is called with NaN values in TensorFlow

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-843`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Segfault if 'tf.histogram_fixed_width' is called with NaN values in TensorFlow Segfault if 'tf.histogram_fixed_width' is called with NaN values in TensorFlow - **OSV ID**: GHSA-xrp2-fhq4-4q3w - **CVE**: CVE-2022-29211 - **CVSS**: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H - *
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Segfault if 'tf.histogram_fixed_width' is called with NaN values in TensorFlow

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-843`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact The implementation of ['tf.histogram_fixed_width'] (https://github.com/tensorflow/tensorflow/blob/f3b9bf4c3c0597563b289c0512e98d4ce81f886e/tensorflow/core/kernels/histogram_op.cc) is vulnerable to a crash when the values array contain 'NaN' elements: 'python import te
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: In Tensorflow before version 2.4.0, when the 'boxes' argument of 'tf.image.crop_and_resize' has a ve

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-843`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # In Tensorflow before version 2.4.0, when the 'boxes' argument of 'tf.image.crop_and_resize' has a very large value, the CPU kernel implementation receives it as a C++ 'nan' floating point value. Attem - **CVE**: CVE-2020-15266 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
