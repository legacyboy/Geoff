# Chrome VRP - Low Hanging Fruit Strategy

## Why Chrome VRP?
- **Public program** - No invitation needed
- **High payouts** - Up to $250,000
- **Well documented** - Clear scope at https://bughunters.google.com/
- **Frequent updates** - New code daily
- **Good response time** - Usually triaged within days

## Scope (Low Hanging Fruit)

### V8 JavaScript Engine
- **Type confusion in TurboFan JIT** → $10,000 - $25,000
- **Bounds check elimination bugs** → $5,000 - $15,000
- **Side-effect modeling errors** → $5,000 - $20,000
- **Garbage collector UAF** → $10,000 - $25,000

### Mojo IPC
- **Use-after-free in IPC** → $5,000 - $15,000
- **Type confusion in bindings** → $3,000 - $10,000
- **Race conditions** → $5,000 - $20,000

### PDFium
- **PDF parsing bugs** → $1,000 - $5,000
- **JavaScript in PDF** → $5,000 - $15,000

## Low Hanging Fruit Targets

### 1. JIT Compiler (V8/TurboFan)
```
Location: v8/src/compiler/
Files: typer.cc, simplifier.cc, effect-control-linearizer.cc

Look for:
- Missing type checks after optimizations
- Bounds check elimination without verification
- Incorrect side-effect modeling
- Redundancy elimination bugs
```

### 2. Parser (V8)
```
Location: v8/src/parsing/
Files: parser.cc, preparser.cc

Look for:
- Stack exhaustion
- OOM in parsing
- Syntax edge cases
```

### 3. Regular Expressions (V8)
```
Location: v8/src/regexp/
Files: regexp-compiler.cc

Look for:
- Backtracking issues
- Quantifier bugs
- Character class errors
```

## Quick Wins Pattern

### Pattern 1: Recent Regressions
1. Check recent commits in target files
2. Look for type system changes
3. Check for missing bounds checks
4. Test with differential fuzzing

### Pattern 2: Configuration Bugs
1. Check for inconsistent flags
2. Look for debug-only checks in release
3. Security-sensitive defaults

### Pattern 3: Error Handling
1. Look for exception paths not cleaning up
2. Early returns leaving dangling pointers
3. Missing error checks after allocations

## Submission Priority

1. **V8 RCE via crafted JS** - $20,000+ (Best ROI)
2. **Mojo IPC UAF** - $10,000+ (Good success rate)
3. **PDFium OOM/parsing** - $1,000-$5,000 (Quick wins)
4. **Extension sandbox escape** - $5,000-$15,000

## Tools

```bash
# Fuzz with differential testing
./tools/gdb/diff_fuzz.py

# Check for specific patterns
grep -r "CHECK.*nullptr" v8/src/compiler/ | head -20

# Find recent security-relevant changes
git log --since="2 weeks ago" -- v8/src/compiler/*.cc | head -50
```

## Submission Template

```markdown
## Summary
[One sentence description]

## Affected Component
[V8 TurboFan/Mojo/PDFium]

## Version
[Chrome version tested]

## Test Case
```javascript
// Minimal PoC
```

## Root Cause
[Technical explanation]

## Impact
[What attacker can do]

## Patch Suggestion
[Optional]
```
