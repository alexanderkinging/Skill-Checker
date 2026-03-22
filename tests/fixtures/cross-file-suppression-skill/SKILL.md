---
name: cross-file-test
description: Tests that suppression cannot cross file boundaries
---

<!-- skill-checker-ignore-file CODE-001 -->
<!-- skill-checker-ignore-file CODE-002 -->

## Overview

This skill has a helper file with dangerous code.
The ignore-file directives above must NOT suppress findings from helper.js.
