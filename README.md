noseatbelt
==========

Remove mitigations from (running!) software.

This library detects and removes mitigations (Spectre, CFG, ...) from a running program.

Currently WIP.

Support
-------

- [x] Linux 64bit
- [ ] Linux 32bit
- [x] Windows 64bit
- [ ] Windows 32bit

Removes
-------

- [x] indirect calls via retpolines (Spectre mitigation)
- [x] returns via return thunks (Spectre mitigation)
- [x] Control Flow Guards (Windows CFI)
- [ ] Return Flow Guards
- [x] jumps that can be inlined
- [ ] calls to functions that can be inlined

Build
-----

```
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Debug ../ #Release is default
make
```

Usage
-----

```
# Measure how long it takes to patch the firefox binary
time LD_PRELOAD=./libnoseatbelt-auto.so firefox --version
```
