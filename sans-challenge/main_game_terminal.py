#!/usr/bin/env python3
"""
SANS HHC 2025 - Access terminal through main game
"""

import asyncio
from pyppeteer import launch

async def solve():
    print("="*60)
    print("SANS HHC 2025 - Main Game Terminal Access")
    print("="*60 + "\n")
    
    browser = await launch(headless=False, args=['--no-sandbox', '--window-size=1400,900'])
    page = await browser.newPage()
    await page.setViewport({'width': 1400, 'height': 900})
    
    # Load main game
    print("[*] Loading main game...")
    await page.goto("https://2025.holidayhackchallenge.com/", {'waitUntil': 'networkidle2'})
    await asyncio.sleep(15)
    
    print("[+] Game loaded")
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/main_game_state.png'})
    
    # Check if we're logged in
    html = await page.content()
    if 'clawdso' in html.lower():
        print("[+] Logged in as clawdso")
    
    # Look for terminal elements or challenge areas
    print("\n[*] Looking for terminal elements...")
    
    # Check for train area or termOrientation
    if 'train' in html.lower():
        print("[+] Train area found in game")
    if 'terminal' in html.lower():
        print("[+] Terminal references found")
    
    # Wait for user to navigate or try to find clickable areas
    print("\n[*] Game loaded in browser.")
    print("[*] If terminals are visible, click one.")
    print("[*] Waiting 20 seconds...")
    await asyncio.sleep(20)
    
    # Get current URL - might have changed to terminal
    current_url = page.url
    print(f"\n[*] Current URL: {current_url}")
    
    if 'wetty-prod' in current_url:
        print("[+] Terminal is open!")
        
        # Wait for terminal to load
        await asyncio.sleep(10)
        
        # Type answer
        textarea = await page.querySelector('textarea.xterm-helper-textarea')
        if textarea:
            print("[*] Typing 'answer'...")
            await textarea.click()
            await asyncio.sleep(1)
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            await page.keyboard.press('Enter')
            await asyncio.sleep(5)
            print("[+] Submitted")
    
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/game_final.png'})
    print("\n[+] Screenshot saved")
    
    await browser.close()
    print("[+] Done")

if __name__ == "__main__":
    asyncio.run(solve())
