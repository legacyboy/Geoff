#!/usr/bin/env python3
"""
SANS HHC 2025 - In-Game Challenge Solver
Stay in the main game window and interact with challenge UI
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
    print("SANS HHC 2025 - In-Game Solver")
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
        print("[+] In game world")

        # Step 3: Enable CTF Mode
        print("\n[*] Enabling CTF Mode...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)

        try:
            ctf = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//*[contains(text(), 'CTF Style')]")))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            print("[!] CTF button issue")

        # Step 4: Open Objectives
        print("\n[*] Opening Objectives...")
        driver.get(
            "https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        # Take screenshot to see state
        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/in_game_objectives.png")

        # Step 5: Analyze the page for challenge input
        print("\n[*] Analyzing page for challenge input...")

        # Look for input elements that might be the challenge answer box
        all_inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(all_inputs)} input elements")

        for i, inp in enumerate(all_inputs):
            try:
                attrs = {
                    "type": inp.get_attribute("type"),
                    "id": inp.get_attribute("id"),
                    "class": inp.get_attribute("class"),
                    "placeholder": inp.get_attribute("placeholder"),
                    "visible": inp.is_displayed()
                }
                print(f"  [Input {i}] {attrs}")
            except:
                pass

        # Look for textareas
        all_textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"\n[*] Found {len(all_textareas)} textarea elements")

        for i, ta in enumerate(all_textareas):
            try:
                attrs = {
                    "id": ta.get_attribute("id"),
                    "class": ta.get_attribute("class"),
                    "visible": ta.is_displayed()
                }
                print(f"  [Textarea {i}] {attrs}")
            except:
                pass

        # Look for contenteditable divs
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"\n[*] Found {len(editables)} contenteditable elements")

        for i, elem in enumerate(editables):
            try:
                print(f"  [Editable {i}] tag={elem.tag_name}, id={elem.get_attribute('id')}, "
                      f"class={elem.get_attribute('class')}, visible={elem.is_displayed()}")
            except:
                pass

        # Look for elements with challenge-related text
        print("\n[*] Looking for challenge-related elements...")
        challenge_elems = driver.find_elements(By.XPATH, "//*[contains(text(), 'termOrientation') or "
                                                            "contains(text(), 'Answer') or "
                                                            "contains(text(), 'answer')]")
        print(f"[*] Found {len(challenge_elems)} challenge-related elements")

        for elem in challenge_elems:
            try:
                print(f"  - {elem.tag_name}: {elem.text[:100]}")
            except:
                pass

        # Step 6: Click "Open Terminal" button
        print("\n[*] Clicking terminal button...")
        try:
            term_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
            term_btn.click()
            print("[+] Clicked terminal button")
            time.sleep(15)
        except Exception as e:
            print(f"[!] Terminal button click failed: {e}")

        print(f"[*] Current URL: {driver.current_url}")

        # Check if a modal or dialog appeared
        print("\n[*] Checking for modal dialogs...")
        dialogs = driver.find_elements(By.CSS_SELECTOR, "[role='dialog'], .modal, .dialog, [class*='modal'], [class*='dialog']")
        print(f"[*] Found {len(dialogs)} potential dialogs")

        for i, dialog in enumerate(dialogs):
            try:
                print(f"\n[Dialog {i}] visible={dialog.is_displayed()}")
                # Look for inputs in dialog
                inputs = dialog.find_elements(By.TAG_NAME, "input")
                print(f"  Inputs in dialog: {len(inputs)}")
                for inp in inputs:
                    print(f"    - type={inp.get_attribute('type')}, placeholder={inp.get_attribute('placeholder')}")
            except:
                pass

        # Check all frames/iframes
        print("\n[*] Checking for frames/iframes...")
        frames = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(frames)} iframes")

        # Take final screenshot
        driver.save_screenshot(
            "/home/claw/.openclaw/workspace/sans-challenge/in_game_analysis.png")
        print("\n[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Done")


if __name__ == "__main__":
    solve()
