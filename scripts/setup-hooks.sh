#!/bin/sh
# Datafew Shield — 安装 git hooks
git config core.hooksPath .githooks
echo "Git hooks installed: pre-commit (lint + quick test), pre-push (full test suite)"
