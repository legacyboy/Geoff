# Chromium Build Configuration (args.gn)

## Target: Zero-Day Hunting Environment
This configuration is optimized for maximum vulnerability detection, providing deep visibility into memory corruption and logic errors.

### Configuration Parameters
```gn
# --- General Build Settings ---
is_debug = true
symbol_level = 2
is_component_build = true
v8_enable_slow_dchecks = true

# --- Sanitizer Suite (The Critical Layer) ---
# AddressSanitizer: Detects UAF, OOB, and heap buffer overflows
is_asan = true

# MemorySanitizer: Detects reads of uninitialized memory
is_msan = true

# UndefinedBehaviorSanitizer: Detects integer overflows, null pointer dereferences, etc.
is_ubsan = true

# --- Optimization & Performance ---
# Disable optimizations that can mask bugs or make debugging difficult
is_optimizeaway_for_testing = true
```

### Deployment Command
Once `gclient sync` is complete, the build will be initialized as follows:
`gn gen out/Default --args='is_debug=true symbol_level=2 is_component_build=true v8_enable_slow_dchecks=true is_asan=true is_msan=true is_ubsan=true'`
