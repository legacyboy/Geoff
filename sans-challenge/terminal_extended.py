#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal Challenge with Extended Wait
"""

import asyncio
from pyppeteer import launch

async def solve():
    print("="*60)
    print("SANS HHC 2025 - Terminal Challenge (Extended Wait)")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    browser = await launch(headless=True, args=['--no-sandbox'])
    page = await browser.newPage()
    await page.setViewport({'width': 1280, 'height': 900})
    
    print("[*] Loading terminal (this may take 30+ seconds)...")
    await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 60000})
    
    # Extended wait for WebSocket connection
    print("[*] Waiting for terminal WebSocket connection...")
    for i in range(6):
        await asyncio.sleep(5)
        print(f"  ... {i+1}/6 (elapsed: {(i+1)*5}s)")
        
        # Check if content appeared
        text = await page.evaluate('''() => {
            const rows = document.querySelectorAll('.xterm-rows div');
            const text = Array.from(rows).map(r => r.textContent).join('\\n');
            return text;
        }''')
        
        if len(text.strip()) > 50:
            print(f"[+] Terminal content detected!")
            break
    
    print(f"\n[*] Terminal content:\n{text[:600] if len(text) > 600 else text}\n")
    
    # Check for challenge prompt
    if "answer" in text.lower() or "challenge" in text.lower():
        print("[+] Challenge prompt detected!")
    
    # Now submit answer
    textarea = await page.querySelector('textarea.xterm-helper-textarea')
    if textarea:
        print("[*] Submitting answer...")
        await textarea.click()
        await asyncio.sleep(1)
        await page.keyboard.type('answer')
        await asyncio.sleep(1)
        await page.keyboard.press('Enter')
        
        print("[*] Waiting for response...")
        await asyncio.sleep(10)
        
        # Check final result
        final_text = await page.evaluate('''() => {
            const rows = document.querySelectorAll('.xterm-rows div');
            return Array.from(rows).map(r => r.textContent).join('\\n');
        }''')
        
        print(f"\n[*] Final terminal content:\n{final_text[-500:] if len(final_text) > 500 else final_text}")
        
        if any(word in final_text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge']):
            print("\n[✓] CHALLENGE COMPLETED!")
        else:
            print("\n[!] Challenge may need manual verification")
    
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/terminal_extended.png'})
    await browser.close()
    print("\n[+] Done")

if __name__ == "__main__":
    asyncio.run(solve())
