noseatbelt
==========

Remove mitigations from (running!) software.

This library detects and removes spectre mitigations from a (running) program
by disassembling it, pattern matching for any calls that use trampolines, and rewriting
them to ordinary calls.

Currently WIP.

Support
-------

- [x] Linux 64bit
- [ ] Linux 32bit
- [ ] Windows 64bit
- [ ] Windows 32bit

Removes
-------

- [x] indirect calls via retpolines (Spectre v1 mitigation)
- [ ] indirect returns via retpolines (Spectre v1 mitigation)
- [ ] return address checks

Build
-----

```
mkdir build
cd build
cmake ../
make
```

Usage
-----

```
# Remove trampolines from an example binary
LD_PRELOAD=$(pwd)/libnoseatbelt-auto.so examples/gcc/example_gcc
# or
LD_PRELOAD=$(pwd)/libnoseatbelt-auto.so examples/gcc/firefox
# ...
```
