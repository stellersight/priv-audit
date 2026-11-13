#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 StellerSight Private Limited
"""Standalone executable launcher for StellerSight Priv-Audit."""

import os
import sys

# Ensure root package directory is in sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from privaudit.cli import main

if __name__ == "__main__":
    sys.exit(main())
