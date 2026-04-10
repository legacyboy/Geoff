# Chromium Garbage Collection (GC) and V8 Sandbox Analysis

## 1. V8 Sandbox Overview
The V8 Sandbox is a security architectural change designed to mitigate the impact of memory corruption vulnerabilities. Instead of relying solely on the OS-level sandbox (which prevents the process from accessing the filesystem or network), the V8 Sandbox focuses on isolating the V8 heap from the rest of the process's address space.

### Design Goals
- **Containment**: Ensure that memory corruption within the V8 heap cannot be used to read or write arbitrary memory outside the sandbox.
- **Address Space Isolation**: Moving critical V8 internals and external pointers into a "Sandbox" region, effectively creating a virtual address space where pointers are relative to a base.
- **Prevention of Arbitrary R/W**: By ensuring that most V8 objects are stored in a contiguous region, an attacker with a primitive to overwrite a pointer in the heap can only overwrite other objects within the sandbox, rather than hijacking a return address on the stack or modifying a function pointer in the libc.

## 2. Garbage Collection (GC) Mechanisms & Vulnerabilities
Chromium's V8 engine uses a sophisticated GC (Orinoco) consisting of a young generation (Scavenger) and an old generation (Major GC/Mark-Compact).

### GC-Related Race Conditions
Race conditions in the GC typically occur during:
- **Concurrent Marking**: When the main thread modifies the object graph while the GC thread is marking it. If the "Write Barrier" fails to correctly notify the GC of the change, objects may be prematurely collected.
- **Concurrent Sweeping**: If a pointer is revived or modified during the sweeping phase, it can lead to Use-After-Free (UAF) scenarios.
- **Incremental Marking**: Pausing and resuming GC marking can lead to "lost" objects if the state isn't perfectly synchronized.

### Memory Corruption Primitives
- **Use-After-Free (UAF)**: The most common GC-related primitive. Occurs when the GC collects an object that is still referenced by the application logic (due to a missing write barrier or logic error).
- **Type Confusion**: Occurs when the GC moves an object or changes its representation, but the application continues to treat it as the old type.
- **Out-of-Bounds (OOB) Access**: Often achieved via array index optimization errors (JIT), which then allows the attacker to read/write adjacent objects in the V8 heap.

## 3. Sandbox Escape Vectors & Bypass Techniques
The V8 Sandbox significantly raises the bar for exploitation, as a traditional "heap overflow $\to$ arbitrary write $\to$ code execution" chain is broken.

### Common Bypass Strategies
- **Sandbox-Internal Primitives**: Attacking the "Sandbox" itself. If an attacker can gain a primitive to write to the Sandbox's internal metadata or the "External Pointer Table," they may be able to leak addresses outside the sandbox.
- **Side-Channel Attacks**: Using timing attacks or speculative execution (Spectre-style) to leak data across the sandbox boundary.
- **Logic Errors in the C++ Bridge**: V8 interacts with Chromium's C++ code via bindings. Vulnerabilities in these bindings (e.g., in the DOM or Mojo IPC) often bypass the V8 sandbox entirely because they operate in the "untrusted" C++ memory space.
- **JIT Spraying/Optimization**: Finding bugs in the TurboFan or Maglev compilers that allow the generation of machine code that performs operations outside the intended sandbox constraints.

## 4. Summary of Current State (2024-2026)
The V8 Sandbox has shifted the exploitation landscape. Most modern exploits now focus on:
1. **Finding a primitive** within the V8 heap (e.g., OOB read/write).
2. **Using that primitive** to manipulate sandbox-internal structures.
3. **Leaking a pointer** to the "outside" world.
4. **Combining** this with a separate vulnerability in the browser process or a Mojo IPC flaw to achieve full RCE.
