#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - TermOrientation Challenge Solver V4
Analyzes page structure and finds the actual challenge input
"""

import asyncio
from pyppeteer import launch

async def solve_term_orientation():
    """Solve termOrientation by properly analyzing the page structure"""
    
    print("="*60)
    print("SANS HHC 2025 - TermOrientation Solver V4")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    print("[*] Launching browser...")
    
    browser = await launch(
        headless=True,
        args=['--no-sandbox', '--disable-setuid-sandbox']
    )
    
    try:
        page = await browser.newPage()
        await page.setViewport({'width': 1280, 'height': 800})
        
        print(f"[*] Navigating...")
        await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 30000})
        print("[+] Loaded")
        
        # Wait for terminal
        print("[*] Waiting 8 seconds for terminal...")
        await asyncio.sleep(8)
        
        # Screenshot to see layout
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_start.png'})
        
        # Analyze page structure
        print("\n[*] Analyzing page structure...")
        
        page_info = await page.evaluate('''() => {
            const info = {
                iframes: document.querySelectorAll('iframe').length,
                textareas: document.querySelectorAll('textarea').length,
                inputs: document.querySelectorAll('input').length,
                divs: document.querySelectorAll('div').length,
                terminalElements: document.querySelectorAll('.terminal, [class*="terminal"], [class*="xterm"]').length
            };
            
            // Get all elements with IDs
            const withIds = Array.from(document.querySelectorAll('[id]')).map(el => ({
                id: el.id,
                tag: el.tagName,
                class: el.className
            }));
            
            // Get terminal-related elements
            const terminalEls = Array.from(document.querySelectorAll('.terminal, [class*="terminal"], [class*="xterm"], .xterm-screen, .xterm-rows')).map(el => ({
                tag: el.tagName,
                class: el.className,
                rect: el.getBoundingClientRect()
            }));
            
            return { info, withIds: withIds.slice(0, 20), terminalEls };
        }''')
        
        print(f"[+] Page elements found:")
        print(f"    Iframes: {page_info['info']['iframes']}")
        print(f"    Textareas: {page_info['info']['textareas']}")
        print(f"    Inputs: {page_info['info']['inputs']}")
        print(f"    Terminal elements: {page_info['info']['terminalElements']}")
        
        print(f"\n[+] Elements with IDs (first 20):")
        for el in page_info['withIds']:
            print(f"    #{el['id']} ({el['tag']}) class={el['class'][:50]}")
        
        print(f"\n[+] Terminal elements:")
        for i, el in enumerate(page_info['terminalEls'][:5]):
            rect = el['rect']
            x = rect.get('x', rect.get('left', 0))
            y = rect.get('y', rect.get('top', 0))
            print(f"    {i+1}. {el['tag']} at ({x:.0f}, {y:.0f})")
        
        # Try to interact with the terminal
        # WeTTy uses xterm.js which has a textarea for input
        print("\n[*] Looking for xterm textarea...")
        
        textarea = await page.querySelector('textarea.xterm-helper-textarea')
        if textarea:
            print("[+] Found xterm textarea!")
            
            # Focus it
            await textarea.focus()
            await asyncio.sleep(1)
            
            # The terminal might have two modes - we need to send input differently
            # Try typing directly in the terminal
            print("[*] Typing 'answer' in terminal...")
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
            
            await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_after_typing.png'})
        
        # Alternative: Look for challenge completion via JavaScript eval
        # Some challenges use __WETTY_EVAL_OUTPUT__
        print("\n[*] Trying JavaScript challenge completion...")
        
        # Check if there's a challenge result function
        challenge_result = await page.evaluate('''() => {
            // Try to find and call any challenge completion functions
            if (typeof __POST_RESULTS__ !== 'undefined') {
                return '__POST_RESULTS__ found';
            }
            if (typeof __WETTY_EVAL_OUTPUT__ !== 'undefined') {
                return '__WETTY_EVAL_OUTPUT__ found';
            }
            if (typeof challengeResult !== 'undefined') {
                return 'challengeResult found';
            }
            return 'No challenge functions found';
        }''')
        
        print(f"[+] Challenge functions: {challenge_result}")
        
        # Check current content
        content = await page.content()
        text = await page.evaluate('() => document.body.innerText')
        
        print(f"\n[*] Checking for completion...")
        if 'congratulations' in text.lower():
            print("[✓] CONGRATULATIONS found!")
        elif 'completed' in text.lower():
            print("[✓] COMPLETED found!")
        elif 'success' in text.lower():
            print("[✓] SUCCESS found!")
        else:
            print("[!] No completion indicators found yet")
        
        # Print first part of text to see what's there
        print(f"\n[*] Page text preview:\n{text[:800]}")
        
        # Save final screenshot
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_final_v4.png'})
        
        await browser.close()
        print("\n[+] Done")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        await browser.close()

if __name__ == "__main__":
    asyncio.run(solve_term_orientation())
