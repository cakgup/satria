# CVSS v4.0 reference engine

Source: https://github.com/FIRSTdotorg/cvss-v4-calculator
Commit: c5b0d409ae9f57c44264c6ce5f27d89298e1d32a
License: BSD-2-Clause (LICENSE).

The six upstream files are retained verbatim. engine.js combines the four data files and cvss_score.js, declares table constants and function-local scratch variables, and adds ES module exports. The scoring arithmetic and lookup tables are unchanged. The browser imports engine.js. The Python server uses cvss 3.6 with app/cvss_reference.py preserving FIRST JavaScript rounding. scripts/check_cvss_reference.py compares both engines across 4096 deterministic vectors.
