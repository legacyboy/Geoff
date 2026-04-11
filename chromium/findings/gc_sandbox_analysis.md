# Chromium Garbage Collection (GC) and V8 Sandbox Analysis

**Date:** April 10, 2026  
**Analyst:** Chromium-GC-Sandbox-Analyst  
**Status:** Comprehensive Analysis  

## Executive Summary

Chromium's V8 JavaScript engine employs a multi-layered security architecture combining garbage collection (GC) with sandboxing mechanisms. This analysis examines memory safety boundaries, sandbox escape vectors via GC-related side effects, and integration points between V8's Orinoco garbage collector and the V8 sandbox. Recent vulnerabilities (2024-2026) demonstrate that while the V8 sandbox raises the exploitation barrier, GC-related race conditions and memory management issues remain fertile ground for sandbox escape primitives.

## 1. V8 Sandbox Architecture Deep Dive

### 1.1 Design Philosophy and Implementation
The V8 sandbox is designed to contain memory corruption within the V8 heap, preventing arbitrary read/write access to the rest of the browser process's address space. Unlike traditional OS-level sandboxes that restrict filesystem/network access, the V8 sandbox focuses on **memory isolation**.

**Key Components:**
- **Sandboxed Heap**: A contiguous memory region (typically 1TB) where all V8 objects reside
- **External Pointer Table (EPT)**: Table for storing pointers to objects outside the sandbox with controlled indirection
- **Sandboxed Pointers**: 40-bit offsets relative to sandbox base address
- **Trusted Space**: Memory outside sandbox accessible via EPT
- **Code Space Isolation**: JIT-compiled code in separate memory region with restricted permissions

### 1.2 Memory Safety Boundaries
- **Sandbox Boundary**: Sandbox base → Sandbox end (hardened boundary checks)
- **External Pointer Boundary**: Controlled access via indirection through EPT
- **Code Space Isolation**: JIT-compiled code in separate memory region with restricted permissions
- **Pointer Compression**: Reduces pointer size from 64-bit to 40-bit, limiting corruption range

### 1.3 Integration with Garbage Collection
The sandbox interacts with GC in critical ways:
1. **Object Movement**: GC compaction moves objects within sandbox while maintaining pointer offsets
2. **External Pointer Tracking**: GC must update EPT entries when external objects move
3. **Memory Layout**: Sandbox contiguous layout affects GC efficiency and fragmentation
4. **Boundary Enforcement**: GC must respect sandbox boundaries during object allocation/movement

## 2. Garbage Collection Architecture & Vulnerabilities

### 2.1 Orinoco GC Components

**Young Generation (Scavenger):**
- Stop-the-world copying collector
- Promotes surviving objects to old generation
- **Vulnerability**: Race conditions during promotion when objects move between spaces

**Old Generation (Major GC/Mark-Compact):**
- Concurrent mark-compact collector
- Background marking thread + main thread compaction
- **Vulnerability**: Concurrent marking races and write barrier failures

**Concurrent Marking:**
- Background thread marks reachable objects while main thread executes JavaScript
- **Vulnerability**: Main thread modifies object graph while GC thread is marking

**Incremental Marking:**
- Interleaved marking pauses with JavaScript execution
- **Vulnerability**: State synchronization failures during pause/resume cycles

### 2.2 GC-Related Race Conditions Analysis

From analysis of `local-heap.cc` and `ephemeron-remembered-set.txt`:

#### 2.2.1 Local Heap State Management Issues
**Location**: `src/heap/local-heap.cc`

**Critical Issues Identified:**
1. **Thread-Local Storage Race Conditions**: Thread-local variable initialization across platforms/build configurations
2. **Inconsistent State Restoration**: Destructor restores `saved_current_isolate_` and `saved_current_local_heap_` without validation
3. **Potential Use-After-Free**: Saved pointers may become dangling if isolates/heaps destroyed prematurely
4. **Missing Bounds Checking**: Debug-only (`DCHECK`) validations removed in release builds

**Exploitation Potential**: Thread state corruption could lead to type confusion between sandbox pointers and external pointers.

#### 2.2.2 Ephemeron Remembered Set Races
**Location**: `src/heap/ephemeron-remembered-set.cc`

**Critical Issues Identified:**
1. **Race Conditions**: Concurrent access to `IndicesSet` structures without proper synchronization
2. **Missing Input Validation**: Slot index calculations without bounds checking
3. **Memory Corruption Primitives**: Out-of-bounds indices stored in remembered sets
4. **Potential Use-After-Free**: `tables_` map storing raw table references without lifetime tracking

**Exploitation Potential**: Corrupted remembered sets could lead to GC marking incorrect objects as reachable/unreachable.

#### 2.2.3 Parser Use-After-Free (Potential)
**Location**: `src/parsing/parser.cc` - `Parser::DefaultConstructor`

**Root Cause**: `function_scope` pointer may be accessed after scope destruction
**Impact**: Could lead to RCE through JIT compilation artifacts
**Status**: PENDING VERIFICATION - Requires deeper analysis of ownership semantics

### 2.3 Memory Corruption Primitives via GC

**Use-After-Free (UAF) Patterns:**
1. **Missing Write Barriers**: GC collects object still referenced by application
2. **Concurrent Collection Race**: Object collected while still in use by another thread
3. **Ephemeron Cycles**: Weak references with cycles not properly handled
4. **Parser Lifetime Bugs**: AST nodes outlive associated scope objects

**Type Confusion via GC:**
1. **Object Movement**: GC moves object, stale references treat it as different type
2. **Map Transition During GC**: Object's hidden class changes during collection
3. **Compaction-Induced Confusion**: Object layout changes after compaction

**Out-of-Bounds (OOB) Access:**
1. **GC-Induced Buffer Corruption**: Overwriting adjacent objects during compaction
2. **Free List Manipulation**: Corrupting allocation metadata to allocate at specific addresses
3. **Sandbox Boundary Overflow**: Integer overflow in sandbox pointer calculations

## 3. Sandbox Escape Vectors via GC Side Effects

### 3.1 Attack Surface Mapping

#### 3.1.1 Sandbox-Internal Primitives
- **EPT Corruption**: Manipulating External Pointer Table entries to point outside sandbox
- **Sandbox Metadata Attacks**: Corrupting sandbox internal structures (allocation metadata, bounds tables)
- **Pointer Compression Bypasses**: Exploiting 40-bit offset arithmetic overflows
- **Code Space Attacks**: JIT-compiled code manipulating sandbox metadata

#### 3.1.2 GC-Assisted Sandbox Escapes

**Scenario 1: GC Race → Sandbox Escape**
```
1. Trigger race condition in concurrent marking
2. Cause type confusion between sandbox pointer and data
3. Use confused pointer to overwrite EPT entry
4. Redirect external pointer to target memory region
5. Read/write outside sandbox via corrupted EPT entry
```

**Scenario 2: Parser UAF → Full Chain**
```
1. Exploit Parser::DefaultConstructor UAF
2. Gain arbitrary read/write within sandbox
3. Locate and corrupt sandbox metadata structures
4. Bypass boundary checks via metadata corruption
5. Combine with Mojo IPC vulnerability for process escape
```

**Scenario 3: JIT Compiler Vulnerability**
```
1. Find bug in TurboFan/Maglev optimization
2. Generate JIT code that violates sandbox assumptions
3. Use JIT spray to create ROP gadgets within sandbox
4. Chain with GC vulnerability to achieve arbitrary code execution
```

### 3.2 Recent Vulnerability Patterns (2024-2026)

Based on recent CVE analysis:

**CVE-2025-13223 / CVE-2025-13224 (November 2025):**
- High-severity type confusion vulnerabilities in V8 engine
- Actively exploited in the wild for RCE within Chrome renderer process
- Could lead to heap corruption enabling arbitrary code execution

**CVE-2025-10585 (March 2026):**
- Critical type confusion vulnerability in V8
- Remote code execution via crafted HTML page
- Actively exploited in the wild
- Demonstrates continued viability of type confusion attacks despite sandbox

**CVE-2024-7971 / CVE-2024-7965 (August 2024):**
- Zero-day vulnerabilities in V8 (type confusion + heap corruption)
- Exploited in the wild, patched August 2024
- Shows persistent memory safety issues in V8

**CVE-2025-9864 (Use-After-Free):**
- UAF vulnerability in V8 JavaScript engine
- CWE-416 (use-after-free)
- Could allow attacker to manipulate freed memory region

**Issue 413364524 (April 2025):**
- Combines UAF with heap spraying techniques
- Allows control of freed objects by spraying heap with specific patterns
- Suggested fixes: improve GC to ensure objects cannot be accessed after being freed

**CVE-2021-37975 (Historical but Illustrative):**
- Garbage collector logic bug causing live objects to be collected
- Leads to UAF for arbitrary objects
- Can be exploited for arbitrary read/write → WebAssembly function body overwrite → arbitrary code execution

### 3.3 Specific Escape Techniques

#### 3.3.1 External Pointer Table (EPT) Manipulation
The EPT is a critical sandbox component that stores pointers to objects outside the sandbox. Corruption of EPT entries provides direct sandbox escape:

**Attack Vectors:**
1. **Type Confusion → EPT Corruption**: Confuse EPT entry with data pointer
2. **OOB Write → EPT Overwrite**: Out-of-bounds write in sandbox overwrites adjacent EPT entry
3. **UAF → EPT Reuse**: Freed EPT entry reused with attacker-controlled data

#### 3.3.2 Sandbox Metadata Attacks
Sandbox internal structures control boundary enforcement and memory layout:

**Target Structures:**
1. **Allocation Metadata**: Corruption could allow allocation outside sandbox
2. **Bounds Tables**: Overwriting could expand sandbox boundaries
3. **Pointer Translation Tables**: Manipulation could redirect sandbox pointers

#### 3.3.3 JIT-Sandbox Interaction Bugs
JIT-compiled code operates with different permissions and memory spaces:

**Exploitation Paths:**
1. **JIT Code Violating Sandbox Assumptions**: Generated code bypasses sandbox checks
2. **JIT Spray ROP Gadgets**: Create executable ROP chain within sandbox
3. **Speculative Execution Bypasses**: Spectre-style attacks leaking sandbox data

## 4. Memory Safety Boundaries Analysis

### 4.1 Boundary Enforcement Mechanisms

#### 4.1.1 Sandbox Pointer Validation
```cpp
// Typical sandbox pointer validation
Address Sandbox::OffsetToAddress(uint64_t offset) {
  if (offset > sandbox_size_) {
    FATAL("Sandbox offset out of bounds");
  }
  return sandbox_base_ + offset;
}
```

**Weaknesses:**
- Integer overflow in offset calculations
- Missing validation in hot paths for performance
- Debug-only checks (`DCHECK`) removed in release builds
- Compiler optimizations removing "unnecessary" checks

#### 4.1.2 GC Write Barriers
Write barriers enforce invariant maintenance during concurrent GC:

**Vulnerability Points:**
1. **Missing Write Barriers**: Certain operations may lack required barriers
2. **Race Conditions**: Barrier execution racing with GC phases
3. **Incorrect Barrier Strength**: Precise vs. imprecise barrier confusion
4. **Compiler Optimizations**: Barriers removed or reordered by optimizer

### 4.2 Cross-Boundary Attacks

#### 4.2.1 From Sandbox to Process Memory
- **EPT Index Corruption**: Modify EPT entries to point outside sandbox
- **Sandbox Size Overflow**: Integer overflow in boundary checks
- **Code Space Attacks**: JIT-compiled code manipulating sandbox metadata
- **Side-Channel Leaks**: Timing/speculative execution leaks across boundary

#### 4.2.2 From GC to Sandbox Escape
- **GC-Induced Type Confusion**: Confuse sandbox pointers with data pointers
- **Allocation Primitive**: Controlled allocation patterns to overwrite metadata
- **Free List Corruption**: Manipulate free lists to allocate at specific addresses
- **Compaction Corruption**: Object movement corrupting adjacent metadata

## 5. Integration Points Between GC and Sandbox

### 5.1 Critical Integration Areas

**1. Object Movement During Compaction:**
- GC compaction moves objects within sandbox
- Must update all references (including sandbox-relative pointers)
- Race conditions could leave stale references

**2. External Pointer Tracking:**
- GC must track objects with references outside sandbox (via EPT)
- EPT updates must be atomic with respect to GC phases
- Missing updates could create dangling external references

**3. Memory Layout Optimization:**
- Sandbox contiguous layout affects GC efficiency
- GC decisions affect sandbox fragmentation
- Optimization conflicts could create security gaps

**4. Concurrent Operations:**
- GC runs concurrently with JavaScript execution
- Sandbox operations must be synchronized with GC phases
- Race windows between GC and sandbox metadata updates

### 5.2 Attack Vectors at Integration Points

**Vector 1: GC-Sandbox Race Conditions**
- GC updating object locations while sandbox processing metadata
- Result: inconsistent view of object layout
- Could allow access to freed or moved objects

**Vector 2: EPT-GC Synchronization Failures**
- GC collects object while EPT still references it
- EPT entry becomes dangling pointer
- Could be reused for sandbox escape

**Vector 3: Compaction-Induced Corruption**
- GC compaction overwrites sandbox metadata
- Metadata corruption bypasses boundary checks
- Could expand sandbox boundaries or disable checks

## 6. Mitigation Analysis

### 6.1 Existing Protections

**Control Flow Integrity (CFI):**
- Prevents vtable/got hijacking
- **Limitation**: Only protects indirect calls

**Address Space Layout Randomization (ASLR):**
- Randomizes memory locations
- **Limitation**: Sandbox reduces effectiveness (contiguous region)

**Data Execution Prevention (DEP/NX):**
- Marks memory as non-executable
- **Limitation**: JIT requires executable memory regions

**Stack Canaries:**
- Detect stack buffer overflows
- **Limitation**: Only protects stack, not heap

### 6.2 Sandbox-Specific Mitigations

**Pointer Compression:**
- Reduces pointer size from 64-bit to 40-bit
- Limits corruption range within sandbox
- **Limitation**: Still allows significant intra-sandbox corruption

**Memory Tagging (ARM MTE):**
- Hardware-assisted memory corruption detection
- **Limitation**: Limited hardware support

**Strict Provenance:**
- Enforces pointer provenance rules
- **Limitation**: Complex to implement correctly

**Bounds Checking:**
- Comprehensive bounds validation
- **Limitation**: Performance impact

### 6.3 GC-Specific Hardening

**Concurrent Safety Verification:**
- Runtime checks for concurrent GC invariants
- **Status**: Partial implementation

**Write Barrier Validation:**
- Verify barrier correctness during testing
- **Status**: Limited runtime validation

**Allocation Sanitizers:**
- Detect use-after-free and buffer overflows
- **Status**: Used in development builds

**Fuzzing Integration:**
- Continuous fuzzing of GC components
- **Status**: Ongoing but incomplete

## 7. Attack Scenarios and Exploit Chains

### 7.1 Modern Exploit Chain (Post-Sandbox)

```
Stage 1: Initial Memory Corruption
  ↓
Type Confusion / UAF / OOB in V8 Heap
  ↓
Arbitrary Read/Write within Sandbox
  ↓
Stage 2: Sandbox Internal Manipulation
  ↓
Locate and Corrupt Sandbox Metadata
  ↓
Bypass Boundary Checks or Leak External Addresses
  ↓
Stage 3: Sandbox Escape
  ↓
EPT Manipulation or Code Space Attack
  ↓
Arbitrary Read/Write Outside Sandbox
  ↓
Stage 4: Process Escape
  ↓
Combine with Mojo IPC / Browser Process Vulnerability
  ↓
Full RCE with Renderer Privileges
```

### 7.2 GC-Specific Attack Scenarios

**Scenario A: Concurrent Marking Race**
```
1. Trigger race in concurrent marking phase
2. Cause inconsistent object graph view
3. Exploit inconsistency for type confusion
4. Use confusion to corrupt sandbox metadata
```

**Scenario B: Ephemeron Cycle Exploit**
```
1. Create complex ephemeron (weak reference) cycle
2. Trigger GC with missing write barrier
3. Cause UAF on cycle participant
4. Use UAF to gain sandbox-internal primitive
```

**Scenario C: Compaction Corruption**
```
1. Force GC compaction with specific object layout
2. Cause compaction to overwrite adjacent metadata
3. Corrupt sandbox boundary information
4. Expand sandbox boundaries or disable checks
```

## 8. Recommendations for Security Research

### 8.1 High-Value Research Areas

1. **Concurrent GC Race Conditions**: Focus on write barrier synchronization, marking race windows
2. **JIT-Sandbox Interactions**: Analyze JIT compiler assumptions about sandbox, speculative execution issues
3. **EPT Corruption Primitives**: Find ways to manipulate External Pointer Table
4. **Sandbox Metadata Attacks**: Target allocation metadata, bounds tables, pointer translation
5. **GC-Sandbox Integration Points**: Race conditions between GC phases and sandbox operations

### 8.2 Testing Methodology

1. **Differential Fuzzing**: Compare sandboxed vs non-sandboxed behavior
2. **Concurrency Testing**: Stress test concurrent GC operations with sandbox interactions
3. **Boundary Value Testing**: Test edge cases in sandbox boundary checks during GC
4. **Composition Attacks**: Combine multiple vulnerabilities for escalation
5. **Lifecycle Testing**: Test object lifetime across GC and sandbox operations

### 8.3 Tooling Suggestions

- **Custom Sanitizers**: For sandbox pointer validation during GC
- **Race Detection**: For GC concurrent operations with sandbox interactions
- **Memory Tagging Analysis**: For ARM MTE bypass research in GC context
- **JIT Behavior Analysis**: For compiler-sandbox interaction bugs
- **EPT Integrity Checking**: Runtime validation of External Pointer Table

## 9. Conclusion

The V8 sandbox represents a significant advancement in Chromium security, fundamentally changing the exploitation landscape. However, it introduces new attack surfaces at the intersection of garbage collection and sandbox enforcement. Memory safety boundaries between the sandbox and process memory remain critical attack vectors.

**Key Findings:**

1. **GC race conditions** remain a viable path to sandbox escape, particularly in concurrent marking and write barrier synchronization
2. **Parser and AST manipulation** can lead to type confusion attacks that bypass sandbox protections
3. **Sandbox metadata structures** are attractive targets for corruption via GC-induced memory errors
4. **EPT manipulation** provides direct sandbox escape vectors when combined with GC vulnerabilities
5. **Integration points** between GC and sandbox operations create novel race condition opportunities

**Trend Analysis (2024-2026):**
Recent vulnerabilities show attackers adapting to the sandbox by:
- Targeting type confusion and UAF within the sandbox
- Chaining sandbox-internal primitives with external vulnerabilities
- Exploiting GC-sandbox integration race conditions
- Using JIT compiler bugs to bypass sandbox assumptions

**Future Research Directions:**
The most promising areas for security research are the integration points between GC, JIT compilation, and sandbox enforcement. These represent the most complex and least-tested components of Chromium's security architecture. Additionally, the shift toward hardware-assisted security (MTE, CET) will create new interaction points with software sandboxing that warrant careful analysis.

## References

1. V8 Sandbox Documentation: https://v8.dev/docs/sandbox
2. Chromium Security Architecture: https://chromium.googlesource.com/chromium/src/+/main/docs/security/
3. Orinoco GC Paper: "Orinoco: parallel and incremental garbage collection for modern applications"
4. Recent CVEs: CVE-2025-13223, CVE-2025-13224, CVE-2025-10585, CVE-2024-7971, CVE-2024-7965
5. Analysis Files:
   - `fabht-research/findings/analysis-local-heap.txt`
   - `fabht-research/findings/analysis-ephemeron-remembered-set.txt`
   - `fabht-research/findings/2026-04-07-v8-parser-uaf-potential.md`
   - `chromium/findings/jit_analysis.md`
   - `chromium/findings/sandbox_analysis.md`
