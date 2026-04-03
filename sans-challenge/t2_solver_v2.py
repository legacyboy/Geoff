#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Terminal 2: "It's All About Defang"
Automated solver using Playwright - Version 2
"""

import asyncio
import re
from playwright.async_api import async_playwright

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"
BASE_URL = "https://2025.holidayhackchallenge.com"

async def solve_terminal():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False, slow_mo=150)
        context = await browser.new_context(viewport={'width': 1920, 'height': 1080})
        page = await context.new_page()
        
        print("[1] Navigating to challenge...")
        await page.goto(f"{BASE_URL}/")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(2)
        
        # Check if already logged in - look for Logout link
        print("[2] Checking login status...")
        logout_link = page.locator('a[href="/logout"]').first
        
        try:
            if await logout_link.is_visible(timeout=3000):
                print("[2] Already logged in!")
            else:
                print("[2] Need to login...")
                # Click login
                await page.click('a:has-text("Login")')
                await asyncio.sleep(2)
                
                # Fill in credentials
                await page.fill('input[type="email"]', EMAIL)
                await page.fill('input[type="password"]', PASSWORD)
                await asyncio.sleep(1)
                
                # Submit login
                await page.click('button[type="submit"]')
                await asyncio.sleep(3)
        except:
            print("[2] Login check failed, assuming logged in")
        
        # Wait for game to load
        print("[3] Waiting for game dashboard...")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(2)
        
        # Click "Play Now!" button to enter the game
        print("[4] Clicking 'Play Now!' to enter game...")
        try:
            await page.click('button:has-text("Play Now!")')
            await asyncio.sleep(5)  # Wait for game to load
        except:
            print("[4] Could not find Play Now button or already in game")
        
        # Wait for game to fully load
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(3)
        
        # Take screenshot to see game state
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_game_loaded.png")
        print("[5] Game loaded screenshot saved: t2_game_loaded.png")
        
        # Look for CTF Mode toggle - enable it
        print("[6] Looking for CTF Mode toggle...")
        try:
            # Look for checkbox or toggle
            ctf_checkbox = page.locator('input[type="checkbox"]').first
            if await ctf_checkbox.is_visible(timeout=3000):
                # Check if not already checked
                is_checked = await ctf_checkbox.is_checked()
                if not is_checked:
                    print("[6] Enabling CTF Mode...")
                    await ctf_checkbox.click()
                    await asyncio.sleep(2)
                else:
                    print("[6] CTF Mode already enabled")
        except:
            print("[6] Could not find CTF toggle, may already be enabled")
        
        # Navigate to badge objectives
        print("[7] Navigating to badge objectives...")
        await page.goto(f"{BASE_URL}/badge?section=objective")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(3)
        
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_badge_page.png")
        print("[7] Badge page screenshot saved: t2_badge_page.png")
        
        # Get page content to find terminals
        content = await page.content()
        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_badge_content.html", "w") as f:
            f.write(content)
        print("[7] Badge HTML saved")
        
        # Look for "It's All About Defang" terminal
        print("[8] Looking for 'It's All About Defang' terminal...")
        
        # Search for defang in the content
        if "defang" in content.lower() or "Defang" in content:
            print("[8] Found 'defang' in page content")
        
        # Try to find and click the terminal
        defang_selectors = [
            'text=It\'s All About Defang',
            'text=All About Defang',
            'text=defang',
            'text=Defang',
            'button:has-text("Open Terminal")',
            'a:has-text("Open Terminal")',
            '.terminal-btn',
            '[data-terminal]',
        ]
        
        terminal_clicked = False
        for selector in defang_selectors:
            try:
                elem = page.locator(selector).first
                count = await elem.count()
                if count > 0:
                    print(f"[8] Found element with selector: {selector}, count: {count}")
                    # Check if visible
                    if await elem.is_visible(timeout=2000):
                        print(f"[8] Clicking element with: {selector}")
                        await elem.click()
                        terminal_clicked = True
                        await asyncio.sleep(3)
                        break
            except Exception as e:
                print(f"[8] Selector {selector} failed: {e}")
                continue
        
        if not terminal_clicked:
            print("[8] Could not click terminal, taking debug screenshot...")
            await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_debug_pre_terminal.png", full_page=True)
        
        # Wait for terminal to open
        print("[9] Waiting for terminal...")
        await asyncio.sleep(3)
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_terminal_open.png", full_page=True)
        print("[9] Terminal screenshot saved: t2_terminal_open.png")
        
        # Look for iframe
        print("[10] Looking for iframe...")
        try:
            iframe = page.locator('iframe').first
            if await iframe.is_visible(timeout=5000):
                print("[10] Found iframe, switching to it...")
                frame = await iframe.content_frame()
                if frame:
                    await asyncio.sleep(3)
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_iframe_content.png")
                    print("[10] Iframe screenshot saved")
                    
                    # Get all text from iframe
                    try:
                        body_text = await frame.locator('body').inner_text(timeout=5000)
                        print(f"[10] Iframe text (first 3000 chars):\n{body_text[:3000]}")
                        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_iframe_text.txt", "w") as f:
                            f.write(body_text)
                    except Exception as e:
                        print(f"[10] Could not get iframe text: {e}")
                    
                    # Save iframe HTML
                    try:
                        iframe_html = await frame.content()
                        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_iframe_full.html", "w") as f:
                            f.write(iframe_html)
                        print("[10] Iframe HTML saved")
                    except Exception as e:
                        print(f"[10] Could not save iframe HTML: {e}")
        except Exception as e:
            print(f"[10] No iframe found: {e}")
        
        # Check main page content too
        main_content = await page.content()
        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_main_full.html", "w") as f:
            f.write(main_content)
        print("[11] Main page HTML saved")
        
        # Keep browser open for manual inspection
        print("\n[PAUSE] Browser will stay open for 60 seconds...")
        await asyncio.sleep(60)
        
        await browser.close()
        print("Browser closed")

if __name__ == "__main__":
    asyncio.run(solve_terminal())
