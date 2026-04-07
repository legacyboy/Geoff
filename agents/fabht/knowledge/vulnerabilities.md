# FabHT Knowledge Base: Chrome Bug Bounty Research

## 1. High-Reward Bug Patterns
The current Chrome/Chromium bounty landscape prioritizes Remote Code Execution (RCE) and Sandbox Escapes.

### A. V8 Engine Vulnerabilities (Initial Entry)
V8 is the primary target for gaining initial code execution within the renderer process.
- **Type Confusion**: The engine misidentifies an object's type, leading to memory corruption. 
- **Use-After-Free (UAF)**: Accessing memory after it has been freed. This is a classic path to heap corruption.
- **Out-of-Bounds (OOB) Read/Write**: Reading or writing outside allocated buffers, often used to establish arbitrary read/write primitives.
- **V8 Sandbox Bypass**: Since the introduction of the V8 Sandbox, bugs that allow memory corruption *outside* the V8 sandbox (e.g., into the rest of the renderer process) are highly valued.

### C. 2026 Emerging Patterns
Recent zero-days indicate a continuing focus on V8 memory safety, object corruption, and GPU-related components.

- **CVE-2026-5281 (April 2026)**: High-severity Use-After-Free (UAF) in **Dawn (WebGPU component)**. Actively exploited. This represents a shift in target area from pure JS/V8 to WebGPU, which provides a powerful new attack surface for memory corruption.
- **CVE-2026-5279 (April 2026)**: Object Corruption in V8 rendering engine.
- **CVE-2026-3910 (March 2026)**: "Inappropriate implementation" in V8. Actively exploited. Leads to RCE within the sandbox via crafted HTML.
- **CVE-2026-3909 (March 2026)**: Out-of-bounds (OOB) write in the **Skia 2D graphics library**. Actively exploited.
- **CVE-2026-1862 (February 2026)**: Type Confusion in V8. Leads to heap corruption and RCE.
- **CVE-2026-2441 (February 2026)**: Use-after-free in Chrome's CSS component.

- **Observation**: Attackers are diversifying targets. While V8 remains central, high-severity zero-days are now appearing in **WebGPU (Dawn)** and **Skia**, suggesting that the "peripheral" components of the renderer are becoming primary targets for memory corruption and potential sandbox escapes.
