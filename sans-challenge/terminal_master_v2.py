#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal Challenge Master Solver V2
"""

import asyncio
from pyppeteer import launch
import json

async def solve():
    print("="*70)
    print("SANS HHC 2025 - Terminal Master Solver V2")
    print("="*70 + "\n")
    
    session_token = "Y2JhZWY0NGYtYTcyMy00YTExLTljYWUtMjM1NTE5YmVmNzM0"
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    browser = await launch(headless=True, args=['--no-sandbox'])
    
    try:
        page = await browser.newPage()
        await page.setViewport({'width': 1280, 'height': 900})
        
        print("[*] Loading terminal...")
        await page.goto(url, {'waitUntil': 'networkidle2'})
        await asyncio.sleep(10)
        
        print("[+] Terminal loaded\n")
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/terminal_start.png'})
        
        # Get terminal content
        print("[*] Reading terminal content...")
        terminal_text = await page.evaluate('''() => {
            const rows = document.querySelectorAll('.xterm-rows div');
            return Array.from(rows).map(r => r.textContent).join('\\n');
        }''')
        
        print("[*] Terminal shows:")
        print(terminal_text[:500] if len(terminal_text) > 500 else terminal_text)
        
        # Find and use the textarea
        print("\n[*] Finding xterm textarea...")
        textarea = await page.querySelector('textarea.xterm-helper-textarea')
        
        if textarea:
            print("[+] Found textarea, typing answer...")
            
            # Click to focus
            await textarea.click()
            await asyncio.sleep(1)
            
            # Type the answer
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            
            # Submit
            await page.keyboard.press('Enter')
            await asyncio.sleep(5)
            
            print("[+] Submitted 'answer'")
            
            # Check result
            final_text = await page.evaluate('''() => {
                const rows = document.querySelectorAll('.xterm-rows div');
                return Array.from(rows).map(r => r.textContent).join('\\n');
            }''')
            
            print("\n[*] Terminal after submission:")
            print(final_text[-400:] if len(final_text) > 400 else final_text)
            
            # Check for success
            if 'congratulations' in final_text.lower() or 'correct' in final_text.lower() or 'completed' in final_text.lower():
                print("\n[✓] SUCCESS!")
            else:
                print("\n[!] No success confirmation in terminal")
                
                # Try JavaScript challenge completion
                print("\n[*] Trying JavaScript completion...")
                await page.evaluate('''() => {
                    if (typeof __POST_RESULTS__ === 'function') {
                        __POST_RESULTS__({answer: 'answer'});
                    }
                    if (window.parent && window.parent !== window) {
                        window.parent.postMessage({type: 'challengeComplete', answer: 'answer'}, '*');
                    }
                }''')
                await asyncio.sleep(3)
        
        # Final screenshot
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/terminal_result.png'})
        print("\n[+] Screenshot saved")
        
        # Check page for any success indicators
        html = await page.content()
        if any(word in html.lower() for word in ['congratulations', 'completed', 'success']):
            print("[✓] Found success indicator in page!")
        
        await browser.close()
        print("\n[+] Done")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(solve())
