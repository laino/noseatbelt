noseatbelt
==========

Remove spectre mitigation from (running!) software.

This library detects and removes spectre mitigations from a (running) program
by disassembling it, pattern matching for any calls that use trampolines, and rewriting
them to ordinary calls.

Currently WIP and more of a POC.
