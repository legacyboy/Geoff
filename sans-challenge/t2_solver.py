#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Terminal 2: "It's All About Defang"
Automated solver using Playwright
"""

import asyncio
import re
from playwright.async_api import async_playwright

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"
BASE_URL = "https://2025.holidayhackchallenge.com"

async def is_visible_safely(locator, timeout=3000):
    """Safely check if element is visible"""
    try:
        return await locator.is_visible(timeout=timeout)
    except:
        return False

async def solve_terminal():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False, slow_mo=100)
        context = await browser.new_context(viewport={'width': 1920, 'height': 1080})
        page = await context.new_page()
        
        print("[1] Navigating to challenge...")
        await page.goto(f"{BASE_URL}/")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(2)
        
        # Check if already logged in
        print("[2] Checking login status...")
        await asyncio.sleep(2)
        
        # Look for login button or user profile
        login_btn = page.locator('text=Login').first
        try:
            if await login_btn.is_visible(timeout=5000):
                print("[2] Login button found, logging in...")
                await login_btn.click()
                await asyncio.sleep(2)
                
                # Fill in credentials
                await page.fill('input[type="email"], input[name="email"], #email', EMAIL)
                await page.fill('input[type="password"], input[name="password"], #password', PASSWORD)
                await asyncio.sleep(1)
                
                # Submit login
                await page.click('button[type="submit"], button:has-text("Login"), input[type="submit"]')
                await asyncio.sleep(3)
        except:
            print("[2] May already be logged in or different auth flow")
        
        # Wait for game to load
        print("[3] Waiting for game to load...")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(3)
        
        # Check for CTF Mode toggle and enable if needed
        print("[4] Checking CTF Mode...")
        try:
            ctf_toggle = page.locator('text=CTF Mode').first
            if await ctf_toggle.is_visible(timeout=5000):
                print("[4] Found CTF toggle")
        except:
            pass
        
        # Navigate to badge section
        print("[5] Navigating to badge objectives...")
        await page.goto(f"{BASE_URL}/badge?section=objective")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(3)
        
        # Take screenshot to see current state
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_step5_badge.png")
        print("[5] Screenshot saved: t2_step5_badge.png")
        
        # Look for "It's All About Defang" terminal link/button
        print("[6] Looking for 'It's All About Defang' terminal...")
        
        # Try various selectors to find the terminal
        terminal_selectors = [
            'text=It\'s All About Defang',
            'text=All About Defang',
            'text=Defang',
            '[data-terminal="its-all-about-defang"]',
            'button:has-text("Open Terminal")',
            'a:has-text("It\'s All About Defang")',
        ]
        
        terminal_found = False
        for selector in terminal_selectors:
            try:
                elem = page.locator(selector).first
                if await elem.is_visible(timeout=3000):
                    print(f"[6] Found terminal with selector: {selector}")
                    await elem.click()
                    terminal_found = True
                    break
            except:
                continue
        
        if not terminal_found:
            print("[6] Could not find terminal link, taking screenshot to debug...")
            await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_debug_no_terminal.png")
            
            # Print page content for debugging
            content = await page.content()
            with open("/home/claw/.openclaw/workspace/sans-challenge/t2_page_debug.html", "w") as f:
                f.write(content)
            print("[6] Page HTML saved to t2_page_debug.html")
        
        await asyncio.sleep(3)
        
        # Wait for terminal iframe/modal to appear
        print("[7] Waiting for terminal to open...")
        await page.wait_for_load_state('networkidle')
        await asyncio.sleep(3)
        
        # Take screenshot of terminal
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_step7_terminal.png", full_page=True)
        print("[7] Terminal screenshot saved: t2_step7_terminal.png")
        
        # Look for iframe containing the terminal
        try:
            iframe = page.locator('iframe').first
            if await iframe.is_visible(timeout=5000):
                print("[8] Found iframe, switching to it...")
                frame = await iframe.content_frame()
                if frame:
                    print("[8] Switched to iframe")
                    
                    # Wait for terminal content to load
                    await asyncio.sleep(3)
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_step8_iframe.png")
                    print("[8] Iframe screenshot saved: t2_step8_iframe.png")
                    
                    # Get frame content for analysis
                    frame_content = await frame.content()
                    with open("/home/claw/.openclaw/workspace/sans-challenge/t2_iframe_content.html", "w") as f:
                        f.write(frame_content)
                    print("[8] Iframe HTML saved to t2_iframe_content.html")
                    
                    # Look for email content
                    print("[9] Looking for email content and IOC extraction tabs...")
                    
                    # Look for tabs
                    tab_selectors = [
                        'text=Domains',
                        'text=IPs', 
                        'text=URLs',
                        'text=Emails',
                        'text=Defang',
                        'button:has-text("Domains")',
                        'button:has-text("IPs")',
                        'button:has-text("URLs")',
                    ]
                    
                    for tab_selector in tab_selectors:
                        try:
                            tab = frame.locator(tab_selector).first
                            if await tab.is_visible(timeout=2000):
                                print(f"[9] Found tab: {tab_selector}")
                        except:
                            pass
                    
                    # Get all text from frame to understand the structure
                    try:
                        all_text = await frame.locator('body').inner_text(timeout=5000)
                        print(f"[9] Frame text content (first 2000 chars):\n{all_text[:2000]}")
                        
                        # Save full text for analysis
                        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_frame_text.txt", "w") as f:
                            f.write(all_text)
                        print("[9] Frame text saved to t2_frame_text.txt")
                    except:
                        print("[9] Could not get frame text")
        except:
            print("[8] No iframe found, checking main page for terminal content...")
            content = await page.content()
            with open("/home/claw/.openclaw/workspace/sans-challenge/t2_main_content.html", "w") as f:
                f.write(content)
            print("[8] Main page content saved")
        
        # Keep browser open for manual inspection if needed
        print("\n[PAUSE] Browser will stay open for 60 seconds for inspection...")
        print("Press Ctrl+C in terminal to close early")
        await asyncio.sleep(60)
        
        await browser.close()
        print("Browser closed")

if __name__ == "__main__":
    asyncio.run(solve_terminal())
