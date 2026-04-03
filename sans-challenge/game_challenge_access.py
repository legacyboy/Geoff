#!/usr/bin/env python3
"""
SANS HHC 2025 - Challenge through game interface
Access challenge via the main game React app
"""

import asyncio
from pyppeteer import launch

async def solve():
    print("="*60)
    print("SANS HHC 2025 - Game Interface Challenge Access")
    print("="*60 + "\n")
    
    browser = await launch(headless=False, args=['--no-sandbox', '--window-size=1400,900'])
    page = await browser.newPage()
    await page.setViewport({'width': 1400, 'height': 900})
    
    # Load main game with auth
    print("[*] Loading game...")
    await page.goto("https://2025.holidayhackchallenge.com/", {'waitUntil': 'networkidle2'})
    await asyncio.sleep(10)
    
    print("[+] Game loaded")
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/game_loaded.png'})
    
    # Try to find and interact with the game world
    # Look for terminal icons, train area, or challenge markers
    
    html = await page.content()
    
    # Check what's loaded
    print("\n[*] Analyzing game state...")
    print(f"  Page title: {await page.title()}")
    
    if 'clawdso' in html.lower():
        print("  [+] Username found in page")
    
    # Look for challenge-related elements
    challenges = await page.querySelectorAll('[class*="challenge"], [class*="terminal"], [id*="terminal"]')
    print(f"  [+] Found {len(challenges)} challenge/terminal elements")
    
    # Try to find the termOrientation challenge
    # It might be accessible via a button or link
    
    # Get all clickable elements and their text
    elements = await page.querySelectorAll('button, a, [role="button"], [onclick]')
    print(f"\n[*] Found {len(elements)} clickable elements")
    
    for i, el in enumerate(elements[:10]):
        try:
            text = await page.evaluate('(el) => el.textContent', el)
            print(f"  {i+1}. {text[:50] if text else '[no text]'}")
        except:
            pass
    
    # Wait for user to manually navigate if needed
    print("\n[*] Browser is open. You can manually navigate to the challenge.")
    print("[*] Waiting 30 seconds...")
    await asyncio.sleep(30)
    
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/game_after_wait.png'})
    
    await browser.close()
    print("\n[+] Done")

if __name__ == "__main__":
    asyncio.run(solve())
