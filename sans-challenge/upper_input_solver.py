#!/usr/bin/env python3
"""
SANS HHC 2025 - Correct Solution
Type in the UPPER challenge input box, not the shell
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
    print("SANS HHC 2025 - Upper Input Box Solution")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 20)

    try:
        # Step 1: Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR,
                            "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR,
                            "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Enter game
        print("\n[*] Entering game...")
        driver.find_element(By.XPATH,
                            "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game")

        # Step 3: Settings → CTF Mode
        print("\n[*] Opening Settings...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)

        print("[*] Enabling CTF Mode...")
        try:
            ctf = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//*[contains(text(), 'CTF Style')]")))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            print("[!] CTF button issue")

        # Step 4: Objectives
        print("\n[*] Opening Objectives...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/before_click.png")

        # Step 5: Click terminal button
        print("\n[*] Clicking terminal button...")
        original_window = driver.current_window_handle

        try:
            term_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
            term_btn.click()
            print("[+] Clicked terminal button")
        except:
            print("[!] Could not click terminal button")

        # Wait for new window
        time.sleep(10)
        windows = driver.window_handles
        print(f"[*] Windows: {len(windows)}")

        if len(windows) > 1:
            for window in windows:
                if window != original_window:
                    driver.switch_to.window(window)
                    print(f"[+] Switched to terminal window")
                    break

        print(f"[*] Current URL: {driver.current_url}")
        time.sleep(10)

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/terminal_open.png")

        # Step 6: Find UPPER challenge input box (NOT the shell)
        print("\n[*] Finding challenge input box...")

        # Look for input fields - NOT the xterm textarea
        try:
            # Method 1: Look for regular input elements (not textarea)
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"[*] Found {len(inputs)} input elements")

            challenge_input = None
            for inp in inputs:
                try:
                    placeholder = inp.get_attribute('placeholder')
                    input_type = inp.get_attribute('type')
                    print(f"  - Input type={input_type}, placeholder={placeholder}")

                    # Look for challenge answer input
                    if placeholder and 'answer' in placeholder.lower():
                        challenge_input = inp
                        print(f"[+] Found challenge input by placeholder")
                        break
                except:
                    pass

            # Method 2: Look for any visible text input
            if not challenge_input:
                for inp in inputs:
                    try:
                        if inp.is_displayed() and inp.is_enabled():
                            challenge_input = inp
                            print(f"[+] Found visible input field")
                            break
                    except:
                        pass

            # Method 3: Look for contenteditable divs
            if not challenge_input:
                print("[*] Looking for contenteditable elements...")
                editables = driver.find_elements(
                    By.CSS_SELECTOR, "[contenteditable='true']")
                print(f"[*] Found {len(editables)} contenteditable elements")
                if editables:
                    challenge_input = editables[0]
                    print(f"[+] Found contenteditable")

            if challenge_input:
                print("\n[*] Clicking challenge input box...")
                challenge_input.click()
                time.sleep(2)

                print("[*] Typing 'answer'...")
                challenge_input.send_keys("answer")
                time.sleep(2)

                print("[*] Submitting...")
                challenge_input.send_keys(Keys.RETURN)
                time.sleep(10)

                print("[+] Answer submitted to challenge input!")
            else:
                print("[!] Could not find challenge input box")

        except Exception as e:
            print(f"[!] Error: {e}")
            import traceback
            traceback.print_exc()

        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/final.png")
        print("\n[+] Screenshot saved")

        # Check result
        text = driver.find_element(By.TAG_NAME, "body").text
        if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge']):
            print("\n[✓] CHALLENGE COMPLETED!")

    except Exception as e:
        print(f"[!] Fatal error: {e}")

    finally:
        input("\nPress Enter to close browser...")
        driver.quit()


if __name__ == "__main__":
    solve()
