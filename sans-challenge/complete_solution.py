#!/usr/bin/env python3
"""
SANS HHC 2025 - Complete Solution
Properly handles terminal button click and new window
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Complete Automated Solution")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 20)

    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR,
                            "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR,
                            "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Enter game
        print("\n[*] Step 2: Entering game...")
        driver.find_element(By.XPATH,
                            "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game world")

        # Step 3: Enable CTF Mode via Settings
        print("\n[*] Step 3: Enabling CTF Mode...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)

        try:
            ctf = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//*[contains(text(), 'CTF Style')]")))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except Exception as e:
            print(f"[!] CTF button issue: {e}")

        # Step 4: Open Objectives
        print("\n[*] Step 4: Opening Objectives...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/objectives_ready.png")

        # Step 5: Click "Open Terminal" button
        print("\n[*] Step 5: Clicking terminal button...")
        time.sleep(3)

        # Store current window handle
        original_window = driver.current_window_handle
        print(f"[*] Original window: {original_window}")

        # Find and click the terminal button
        try:
            # Look for "Open Terminal" button
            term_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
            print("[+] Found 'Open Terminal' button")

            # Click it
            term_btn.click()
            print("[+] Clicked terminal button")

        except Exception as e:
            print(f"[!] Button error: {e}")
            # Try alternative selector
            try:
                term_btn = driver.find_element(
                    By.CSS_SELECTOR, "button.terminal-btn")
                term_btn.click()
                print("[+] Clicked terminal button (alt)")
            except:
                print("[!] Could not click terminal button")

        # Wait for new window to open
        print("\n[*] Waiting for terminal window...")
        time.sleep(10)

        # Check for new window
        windows = driver.window_handles
        print(f"[*] Total windows: {len(windows)}")

        if len(windows) > 1:
            # Switch to new window (terminal)
            for window in windows:
                if window != original_window:
                    driver.switch_to.window(window)
                    print(f"[+] Switched to terminal window: {window}")
                    break

        print(f"[*] Current URL: {driver.current_url}")
        time.sleep(10)  # Wait for terminal to load

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/terminal_loaded.png")

        # Step 6: Solve the challenge
        if "wetty" in driver.current_url:
            print("\n[*] Step 6: Solving challenge...")
            time.sleep(10)

            try:
                # Find the xterm textarea
                textarea = driver.find_element(
                    By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                print("[+] Found terminal textarea")

                # Click and enter answer
                textarea.click()
                time.sleep(2)
                print("[*] Typing 'answer'...")
                textarea.send_keys("answer")
                time.sleep(2)
                print("[*] Submitting...")
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)

                print("[+] Answer submitted")

                # Check for success
                text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']):
                    print("\n" + "=" * 60)
                    print("[✓] CHALLENGE SOLVED!")
                    print("=" * 60)
                else:
                    print("\n[!] Check screenshot for result")

            except Exception as e:
                print(f"[!] Error solving: {e}")
        else:
            print(f"\n[!] Terminal not in URL: {driver.current_url}")

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/final_result.png")
        print("\n[+] Final screenshot saved")

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Browser closed")


if __name__ == "__main__":
    solve()
