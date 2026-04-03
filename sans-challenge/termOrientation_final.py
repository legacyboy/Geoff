#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - TermOrientation Final Attempt
Analyzes the actual terminal content
"""

import asyncio
from pyppeteer import launch

async def solve_term_orientation():
    """Final attempt - get terminal text directly from xterm"""
    
    print("="*60)
    print("SANS HHC 2025 - TermOrientation Final Solver")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    browser = await launch(headless=True, args=['--no-sandbox', '--disable-setuid-sandbox'])
    
    try:
        page = await browser.newPage()
        await page.setViewport({'width': 1280, 'height': 800})
        
        await page.goto(url, {'waitUntil': 'networkidle2'})
        print("[+] Page loaded")
        
        await asyncio.sleep(8)
        print("[+] Waited for terminal")
        
        # Get the actual terminal content from xterm
        terminal_text = await page.evaluate('''() => {
            // Try to get text from xterm instance
            const xterm = window.term || window.xterm;
            if (xterm && xterm._core) {
                // Get buffer text
                const buffer = xterm._core._bufferService.buffer;
                let text = '';
                for (let i = 0; i < buffer.length; i++) {
                    text += buffer.getLine(i).translateToString() + '\n';
                }
                return text;
            }
            
            // Alternative: get from DOM
            const termRows = document.querySelectorAll('.xterm-rows div');
            if (termRows.length > 0) {
                return Array.from(termRows).map(row => row.textContent).join('\n');
            }
            
            return "Could not extract terminal text";
        }''');
        
        print("\n[*] Terminal content:")
        print(terminal_text[:1000])
        
        # Check if challenge prompt is visible
        if "Type answer" in terminal_text or "Enter the answer" in terminal_text:
            print("\n[+] Challenge prompt detected!")
        
        # Try to submit by typing in the terminal
        print("\n[*] Typing 'answer' in terminal...")
        textarea = await page.querySelector('textarea.xterm-helper-textarea')
        if textarea:
            await textarea.focus()
            await asyncio.sleep(1)
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            await page.keyboard.press('Enter')
            await asyncio.sleep(5)
            
            print("[+] Typed and submitted")
        
        # Get updated terminal text
        final_text = await page.evaluate('''() => {
            const termRows = document.querySelectorAll('.xterm-rows div');
            if (termRows.length > 0) {
                return Array.from(termRows).map(row => row.textContent).join('\n');
            }
            return "";
        }''');
        
        print("\n[*] Final terminal content:")
        print(final_text[-500:] if len(final_text) > 500 else final_text)
        
        # Check for success
        success_indicators = ['congratulations', 'correct', 'completed', 'success', 'badge', 'award', 'well done', '✓']
        if any(ind in final_text.lower() for ind in success_indicators):
            print("\n[✓] SUCCESS DETECTED!")
        else:
            print("\n[!] No success indicators found")
        
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_final.png'})
        print("\n[+] Screenshot saved")
        
        await browser.close()
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        await browser.close()

if __name__ == "__main__":
    asyncio.run(solve_term_orientation())
