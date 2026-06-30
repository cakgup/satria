#!/usr/bin/env bash
set -euo pipefail
cat <<'NOTE'
Greenbone/OpenVAS bootstrap sengaja tidak di-embed sebagai satu container karena upstream Greenbone Community Containers adalah stack multi-service.
Ikuti panduan resmi:
https://greenbone.github.io/docs/latest/22.4/container/index.html

Setelah Greenbone berjalan, isi GREENBONE_* pada .env SATRIA dan implementasikan connector GMP di app/scanner_runner.py.
NOTE
