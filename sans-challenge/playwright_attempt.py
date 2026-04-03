#!/usr/bin/env python3
"""
SANS HHC 2025 - Playwright Automation
Uses Playwright with auto-waiting features for reliable element interaction
"""

from playwright.sync_api import sync_playwright, expect
import time
import re

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve_hhc():
    print("=" * 60)
    print("SANS HHC 2025 - Playwright Automation")
    print("=" * 60 + "\n")

    with sync_playwright() as p:
        # Launch browser with specific viewport
        print("[*] Launching browser...")
        browser = p.chromium.launch(
            headless=False,
            args=["--window-size=1400,900"]
        )
        context = browser.new_context(
            viewport={"width": 1400, "height": 900},
            accept_downloads=True
        )
        page = context.new_page()

        try:
            # Step 1: Login
            print("[*] Step 1: Logging in...")
            page.goto("https://account.counterhack.com?ref=hhc25")
            
            # Wait for email field and fill it (Playwright auto-waits)
            email_field = page.locator("input[type='email']")
            email_field.wait_for(state="visible", timeout=10000)
            email_field.fill(EMAIL)
            print("[+] Email filled")
            
            # Fill password
            password_field = page.locator("input[type='password']")
            password_field.fill(PASSWORD)
            print("[+] Password filled")
            
            # Submit login and wait for navigation
            print("[*] Login submitted")
            password_field.press("Enter")
            
            # Wait for the page to load after login
            page.wait_for_load_state("networkidle", timeout=15000)
            time.sleep(5)
            print(f"[+] After login, URL: {page.url}")

            # Step 2: Enter game
            print("\n[*] Step 2: Entering game...")
            
            # Look for and click Play Now button using Playwright's auto-waiting
            try:
                play_now_btn = page.locator("button:has-text('Play Now')")
                play_now_btn.wait_for(state="visible", timeout=10000)
                print("[+] Found Play Now button")
                
                # Click and wait for navigation
                play_now_btn.click()
                page.wait_for_load_state("networkidle", timeout=20000)
                time.sleep(15)  # Give game time to initialize
                print(f"[+] In game world: {page.url}")
            except Exception as e:
                print(f"[!] Play Now button issue: {e}")
                # Navigate directly as fallback
                page.goto("https://2025.holidayhackchallenge.com/")
                page.wait_for_load_state("networkidle")
                time.sleep(15)
                print(f"[+] Direct navigation to game: {page.url}")

            # Step 3: Enable CTF Mode via Settings
            print("\n[*] Step 3: Enabling CTF Mode...")
            page.goto("https://2025.holidayhackchallenge.com/badge?section=setting")
            page.wait_for_load_state("networkidle")
            time.sleep(5)
            
            page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/playwright_settings.png")
            print("[+] Settings screenshot saved")

            try:
                # Look for CTF Mode/Style toggle
                ctf_found = False
                
                # Try finding by text
                for text in ["CTF Mode", "CTF Style", "CTF"]:
                    if ctf_found:
                        break
                    try:
                        locator = page.get_by_text(text, exact=False)
                        if locator.count() > 0:
                            # Click the toggle near the text
                            locator.first.click()
                            print(f"[+] CTF Mode enabled (clicked on '{text}')")
                            ctf_found = True
                            break
                    except:
                        pass
                
                # Try finding any checkbox if text approach failed
                if not ctf_found:
                    try:
                        checkboxes = page.locator("input[type='checkbox']")
                        if checkboxes.count() > 0:
                            checkboxes.first.click()
                            print("[+] Clicked first checkbox (likely CTF)")
                            ctf_found = True
                    except:
                        pass
                
                if not ctf_found:
                    print("[!] Could not find CTF toggle, may already be enabled")
                    
                time.sleep(3)
            except Exception as e:
                print(f"[!] CTF toggle issue: {e}")
                print("[*] Continuing anyway...")

            # Step 4: Open Objectives
            print("\n[*] Step 4: Opening Objectives...")
            page.goto("https://2025.holidayhackchallenge.com/badge?section=objective")
            page.wait_for_load_state("networkidle")
            time.sleep(10)
            print("[+] Objectives loaded")

            page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/playwright_objectives.png")
            print("[+] Objectives screenshot saved")

            # Step 5: Find and click "Open Terminal" button
            print("\n[*] Step 5: Finding and clicking terminal button...")
            
            # Try multiple strategies to find the button using Playwright's auto-waiting
            term_btn = None
            
            # Strategy 1: Direct text search
            for btn_text in ["Open Terminal", "Terminal", "Open"]:
                if term_btn is not None:
                    break
                try:
                    btn = page.locator(f"button:has-text('{btn_text}')")
                    btn.wait_for(state="visible", timeout=5000)
                    if btn.count() > 0:
                        term_btn = btn.first
                        print(f"[+] Found terminal button with text: {btn_text}")
                        break
                except:
                    pass
            
            # Strategy 2: Get by text (more flexible)
            if term_btn is None:
                try:
                    btn = page.get_by_text("Open Terminal", exact=False)
                    btn.wait_for(state="visible", timeout=5000)
                    term_btn = btn
                    print("[+] Found terminal button using get_by_text")
                except:
                    pass
            
            # Strategy 3: Look for button containing "terminal" class
            if term_btn is None:
                try:
                    btn = page.locator("[class*='terminal']")
                    btn.wait_for(state="visible", timeout=5000)
                    if btn.count() > 0:
                        term_btn = btn.first
                        print("[+] Found terminal button by class")
                except:
                    pass
            
            if term_btn is None:
                raise Exception("Could not find terminal button with any strategy")
            
            # Store current window handle (page) count
            pages_before = len(context.pages)
            print(f"[*] Pages before click: {pages_before}")
            
            # Click the button - terminal may open in new window or same window
            term_btn.click()
            print("[+] Clicked terminal button")
            
            # Wait for new page to potentially open
            time.sleep(10)
            
            pages_after = len(context.pages)
            print(f"[*] Pages after click: {pages_after}")
            
            # Determine which page is the terminal
            if pages_after > pages_before:
                # New window opened
                terminal_page = context.pages[-1]  # Get the newest page
                print(f"[+] Terminal opened in new window: {terminal_page.url}")
            else:
                # Terminal opened in same window
                terminal_page = page
                print(f"[*] Terminal may have opened in same window: {terminal_page.url}")
            
            # Wait for terminal to load
            terminal_page.wait_for_load_state("networkidle", timeout=20000)
            time.sleep(10)
            
            print(f"[*] Terminal URL: {terminal_page.url}")
            terminal_page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/playwright_terminal.png")
            print("[+] Terminal screenshot saved")

            # Step 6: Solve the challenge
            if "wetty" in terminal_page.url:
                print("\n[*] Step 6: Solving challenge...")
                time.sleep(10)  # Wait for terminal fully loaded

                try:
                    # Find the xterm textarea using Playwright's auto-waiting
                    textarea = terminal_page.locator("textarea.xterm-helper-textarea")
                    textarea.wait_for(state="visible", timeout=20000)
                    print("[+] Found terminal textarea")

                    # Click and type answer
                    textarea.click()
                    time.sleep(2)
                    print("[*] Typing 'answer'...")
                    textarea.fill("answer")
                    time.sleep(2)
                    print("[*] Submitting...")
                    textarea.press("Enter")
                    time.sleep(10)

                    print("[+] Answer submitted")

                    # Check for success
                    body_text = terminal_page.locator("body").inner_text()
                    success_words = ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']
                    if any(word in body_text.lower() for word in success_words):
                        print("\n" + "=" * 60)
                        print("[✓] CHALLENGE SOLVED!")
                        print("=" * 60)
                    else:
                        print("\n[!] Check screenshot for result")

                except Exception as e:
                    print(f"[!] Error solving: {e}")
                    import traceback
                    traceback.print_exc()
            else:
                print(f"\n[!] Terminal not in URL: {terminal_page.url}")
                print("[*] Dumping page content for debugging...")
                print(terminal_page.content()[:2000])

            # Final screenshot
            terminal_page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/playwright_final.png")
            print("\n[+] Final screenshot saved")

            # Keep browser open for user to see result
            input("\nPress Enter to close browser...")

        except Exception as e:
            print(f"\n[!] Fatal error: {e}")
            import traceback
            traceback.print_exc()
            
            # Save error screenshot
            try:
                page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/playwright_error.png")
                print("[+] Error screenshot saved")
            except:
                pass

        finally:
            browser.close()
            print("[+] Browser closed")


if __name__ == "__main__":
    solve_hhc()
