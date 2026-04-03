#!/usr/bin/env python3
"""
SANS HHC 2025 - TermOrientation
Try typing at different positions within the terminal
"""

import asyncio
from pyppeteer import launch

async def solve():
    print("="*60)
    print("SANS HHC 2025 - TermOrientation Position Solver")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    browser = await launch(headless=True, args=['--no-sandbox'])
    page = await browser.newPage()
    await page.setViewport({'width': 1280, 'height': 800})
    
    await page.goto(url, {'waitUntil': 'networkidle2'})
    await asyncio.sleep(8)
    
    print("[+] Terminal loaded")
    
    # The textarea is at (160, 304) - that's the terminal
    # But the challenge might have an input at the top
    # Let's try clicking at various Y positions and typing
    
    y_positions = [100, 150, 200, 250, 300, 350, 400]
    x_center = 640
    
    for y in y_positions:
        print(f"\n[*] Trying click at ({x_center}, {y})...")
        
        await page.mouse.click(x_center, y)
        await asyncio.sleep(1)
        
        # Clear any existing input
        await page.keyboard.press('Escape')
        await asyncio.sleep(0.5)
        
        # Type answer
        print("  [*] Typing 'answer'...")
        await page.keyboard.type('answer')
        await asyncio.sleep(1)
        
        # Submit
        print("  [*] Pressing Enter...")
        await page.keyboard.press('Enter')
        await asyncio.sleep(4)
        
        # Check result
        html = await page.content()
        text = await page.evaluate('() => document.body.innerText')
        
        # Check various success indicators
        if any(word in html.lower() for word in ['congratulations', 'completed']):
            print(f"  [✓] SUCCESS at Y={y}!")
            break
        elif any(word in text.lower() for word in ['correct', 'success']):
            print(f"  [✓] SUCCESS at Y={y}!")
            break
        else:
            print(f"  [!] No success at Y={y}")
    
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_positions.png'})
    print("\n[+] Final screenshot saved")
    
    await browser.close()

if __name__ == "__main__":
    asyncio.run(solve())
