#!/bin/bash

set -e

V8_SRC="$HOME/chromium/src/v8/src"
SPIDERMONKEY_SRC="$HOME/firefox/mozilla-central/js/src"
PDFIUM_SRC="$HOME/chromium/src/third_party/pdfium"
OUTPUT_DIR="$HOME/chromium/findings/agent3"

mkdir -p "$OUTPUT_DIR"

analyze_v8() {
    echo "=== Analyzing V8 JavaScript Engine ===" > "$OUTPUT_DIR/chromium_deep_analysis.txt"
    
    # 1. Find all JIT compiler files
    echo "## JIT Compiler Files" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    find "$V8_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(jit|compiler|maglev|turbofan|baseline|codegen)" | \
        head -50 >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    
    echo "" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    echo "## Memory Management Files" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    find "$V8_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(heap|objects|handles|memory)" | \
        head -50 >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    
    # Sample key files for detailed analysis
    echo "" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    echo "=== Detailed Analysis of Key Files ===" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    
    # Check for known vulnerability patterns
    echo "## Searching for Integer Overflows" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    grep -r -n -B2 -A2 "integer.*overflow\|int.*overflow\|size_t.*overflow\|CheckBounds\|DCHECK" \
        "$V8_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/chromium_deep_analysis.txt" 2>/dev/null || true
    
    echo "" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    echo "## Searching for Memory Safety Issues" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    grep -r -n -B2 -A2 "use.*after.*free\|UAF\|free.*after\|delete.*after\|heap.*spray\|buffer.*overflow" \
        "$V8_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/chromium_deep_analysis.txt" 2>/dev/null || true
    
    echo "" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    echo "## Searching for Type Confusion Patterns" >> "$OUTPUT_DIR/chromium_deep_analysis.txt"
    grep -r -n -B2 -A2 "type.*confusion\|cast.*type\|static_cast\|reinterpret_cast\|type.*check" \
        "$V8_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/chromium_deep_analysis.txt" 2>/dev/null || true
}

analyze_spidermonkey() {
    echo "=== Analyzing Firefox SpiderMonkey ===" > "$OUTPUT_DIR/firefox_deep_analysis.txt"
    
    echo "## JIT Compiler Files" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    find "$SPIDERMONKEY_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(jit|ion|baseline|codegen)" | \
        head -50 >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    
    echo "" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    echo "## GC and Memory Files" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    find "$SPIDERMONKEY_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(gc|memory|heap)" | \
        head -50 >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    
    # Search for vulnerability patterns
    echo "" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    echo "=== Searching for Integer Overflow Patterns ===" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    grep -r -n -B2 -A2 "integer.*overflow\|int.*overflow\|size_t.*overflow\|MOZ_ASSERT\|JS_ASSERT" \
        "$SPIDERMONKEY_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/firefox_deep_analysis.txt" 2>/dev/null || true
    
    echo "" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    echo "=== Searching for Memory Safety Issues ===" >> "$OUTPUT_DIR/firefox_deep_analysis.txt"
    grep -r -n -B2 -A2 "use.*after.*free\|UAF\|free\|delete\|buffer.*overflow\|bounds.*check" \
        "$SPIDERMONKEY_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/firefox_deep_analysis.txt" 2>/dev/null || true
}

analyze_pdfium() {
    echo "=== Analyzing PDFium ===" > "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    
    echo "## Parser Files" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    find "$PDFIUM_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(parser|parse|decode|stream)" | \
        head -50 >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    
    echo "" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    echo "## Memory Management Files" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    find "$PDFIUM_SRC" -type f \( -name '*.cc' -o -name '*.cpp' -o -name '*.h' \) | \
        grep -E "(memory|alloc|buffer)" | \
        head -50 >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    
    # Search for PDF-specific vulnerabilities
    echo "" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    echo "=== Searching for Integer Overflow Patterns ===" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    grep -r -n -B2 -A2 "integer.*overflow\|int.*overflow\|size_t.*overflow\|CHECK\|DCHECK" \
        "$PDFIUM_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/pdfium_deep_analysis.txt" 2>/dev/null || true
    
    echo "" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    echo "=== Searching for Memory Safety Issues ===" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    grep -r -n -B2 -A2 "use.*after.*free\|UAF\|buffer.*overflow\|heap.*overflow\|stack.*overflow" \
        "$PDFIUM_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/pdfium_deep_analysis.txt" 2>/dev/null || true
    
    echo "" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    echo "=== Searching for Type Confusion ===" >> "$OUTPUT_DIR/pdfium_deep_analysis.txt"
    grep -r -n -B2 -A2 "static_cast\|reinterpret_cast\|dynamic_cast\|type.*confusion" \
        "$PDFIUM_SRC" --include="*.cc" --include="*.cpp" --include="*.h" | \
        head -100 >> "$OUTPUT_DIR/pdfium_deep_analysis.txt" 2>/dev/null || true
}

echo "Starting deep analysis of all three codebases..."
analyze_v8
analyze_spidermonkey
analyze_pdfium
echo "Analysis complete. Output saved to $OUTPUT_DIR/"