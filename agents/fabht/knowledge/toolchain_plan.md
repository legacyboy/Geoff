# Toolchain & VM Deployment Plan - FabHT

**Target VM:** Ubuntu (10.0.2.15)

## 1. Toolchain Requirements
To effectively hunt for Chrome/V8 bugs, the VM needs a full build environment and specific analysis tools.

### A. Build Dependencies
Chromium is massive. We need `depot_tools` and a high-capacity build environment.
- **depot_tools**: The essential toolset for Chromium development (fetch, gclient, gn, ninja).
- **Build Tools**: `gcc`, `g++`, `python3`, `git`, `curl`, `wget`.
- **Hardware Requirements**: Minimum 16GB RAM (32GB+ preferred) and 100GB+ disk space for a full checkout.

### B. Fuzzing & Testing Suite
- **AFL++**: For general binary and library fuzzing.
- **libFuzzer**: Integrated with Chromium/V8 for targeted function fuzzing.
- **d8**: The V8 shell used for triggering and verifying JS-based crashes.
- **AddressSanitizer (ASan)**: Essential for detecting UAF and OOB errors.

### C. Debugging & Analysis
- **GDB / LLDB**: For analyzing crash dumps.
- **RR (Record and Replay)**: For deterministic debugging of complex V8 crashes.
- **V8-specific flags**: `--allow-natives-syntax` for inspecting heap objects.

## 2. Setup Process (Sequential)

### Phase 1: Base System Prep
1. Update packages and install essential build-essential and python libraries.
2. Configure git identity.

### Phase 2: Depot Tools Installation
1. Clone `depot_tools` to `~/depot_tools`.
2. Add `depot_tools` to the system PATH.
3. Run `gclient` to bootstrap.

### Phase 3: Chromium/V8 Checkout
1. Create a directory for the source (e.g., `~/chromium`).
2. Run `fetch chromium` (Note: This takes several hours and massive bandwidth).
3. Run `gclient sync`.

### Phase 4: Build Configuration
1. Use `gn` to generate build files with ASan enabled:
   - `is_asan = true`
   - `is_debug = true`
2. Compile V8/d8 using `ninja`.

## 3. Immediate Execution Script (First Step)
The first set of commands will focus on "Phase 1" and "Phase 2" to ensure the environment is ready for the heavy lifting.
