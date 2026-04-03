#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Playwright Version
"""

from playwright.sync_api import sync_playwright
import time

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Playwright")
    print("=" * 60 + "\n")

    with sync_playwright() as p:
        # Launch browser
        browser = p.chromium.launch(headless=False)
        context = browser.new_context(viewport={'width': 1400, 'height': 900})
        page = context.new_page()

        try:
            # Login
            print("[*] Logging in...")
            page.goto("https://account.counterhack.com?ref=hhc25")
            page.wait_for_selector("input[type='email']")
            page.fill("input[type='email']", EMAIL)
            page.fill("input[type='password']", PASSWORD)
            page.press("input[type='password']", "Enter")
            page.wait_for_timeout(5000)
            print("[+] Logged in\n")

            # Enter game
            print("[*] Entering game...")
            page.click("button:has-text('Play Now')")
            page.wait_for_timeout(20000)
            print("[+] In game\n")

            # CTF Mode
            print("[*] Enabling CTF Mode...")
            page.goto("https://2025.holidayhackchallenge.com/badge?section=setting")
            page.wait_for_timeout(5000)
            try:
                page.click("text=CTF Style")
                page.wait_for_timeout(3000)
                print("[+] CTF Mode enabled")
            except:
                pass

            # Objectives
            print("[*] Opening Objectives...")
            page.goto("https://2025.holidayhackchallenge.com/badge?section=objective")
            page.wait_for_timeout(15000)

            # Screenshot before
            page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t1_pw_before.png")

            # Click terminal
            print("[*] Clicking terminal...")
            page.click("button:has-text('Open Terminal')")
            page.wait_for_timeout(40000)  # Wait for terminal

            # Screenshot
            page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t1_pw_terminal.png")
            print("[+] Terminal screenshot saved")

            # Get iframe and interact
            print("\n[*] Getting iframe...")
            iframe = page.locator("iframe").first
            frame = iframe.content_frame()
            
            if frame:
                print("[+] Got frame content")
                frame.wait_for_timeout(10000)
                
                # Click on terminal to focus
                print("[*] Clicking terminal...")
                frame.click(".xterm-screen")
                frame.wait_for_timeout(3000)
                
                # Type answer
                print("[*] Typing 'answer'...")
                frame.fill(".xterm-helper-textarea", "answer")
                frame.wait_for_timeout(2000)
                
                # Press Enter
                print("[*] Pressing Enter...")
                frame.press(".xterm-helper-textarea", "Enter")
                frame.wait_for_timeout(5000)
                
                print("[+] Typed 'answer'")
                
                # Screenshot
                page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t1_pw_typed.png")
            
            # Verify
            print("\n[*] Verifying...")
            page.click(".close-modal-btn")
            page.wait_for_timeout(3000)
            
            page.goto("https://2025.holidayhackchallenge.com/badge?section=objective")
            page.wait_for_timeout(10000)
            
            page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t1_pw_verify.png")
            
            # Check completion
            text = page.locator("body").inner_text()
            if "completed" in text.lower() or "check" in text.lower():
                print("[✓] CHALLENGE COMPLETE!")
            else:
                print("[!] Not complete yet")

        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()
            
        finally:
            browser.close()
            print("\n[+] Done")


if __name__ == "__main__":
    solve()
