#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2 - Exploration
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 2 - Exploration")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Objectives
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)
        
        # Check what objectives are visible
        print("\n[*] Checking available objectives...")
        text = driver.find_element(By.TAG_NAME, "body").text
        print(f"Page text:\n{text[:800]}\n")
        
        # Look for Terminal 2 button
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"[*] Found {len(buttons)} buttons")
        for btn in buttons:
            try:
                txt = btn.text
                if 'terminal' in txt.lower() or 'open' in txt.lower():
                    print(f"  - {txt}")
            except:
                pass

        # Try to find and click Terminal 2
        print("\n[*] Looking for Terminal 2 button...")
        try:
            # Look for button with "Second" or "2nd" or just the second terminal button
            driver.find_element(By.XPATH, "//button[contains(text(), 'Second Terminal')]").click()
            print("[+] Opened Second Terminal")
        except:
            try:
                driver.find_element(By.XPATH, "//button[contains(text(), '2nd')]").click()
                print("[+] Opened 2nd Terminal")
            except:
                try:
                    # Find all terminal buttons and click the second one
                    term_buttons = driver.find_elements(By.XPATH, "//button[contains(text(), 'Open Terminal')]")
                    if len(term_buttons) >= 2:
                        term_buttons[1].click()
                        print("[+] Opened second terminal button")
                    else:
                        print("[!] Only one terminal button found")
                        # Try clicking the first one anyway
                        if term_buttons:
                            term_buttons[0].click()
                            print("[+] Opened first terminal")
                except Exception as e:
                    print(f"[!] Error: {e}")

        time.sleep(40)
        print("[+] Terminal opened")
        
        # Take screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_explore.png")
        print("[+] Screenshot saved")
        
        # Look for challenge input in parent modal (above iframe)
        print("\n[*] Looking for challenge input...")
        
        # Method 1: Look for text containing challenge instructions
        body_text = driver.find_element(By.TAG_NAME, "body").text
        if "here:" in body_text.lower() or ">" in body_text:
            print("[+] Found challenge text in modal")
            # Find position of ">"
            idx = body_text.find(">")
            if idx > 0:
                print(f"Context around >: ...{body_text[max(0,idx-50):idx+50]}...")
        
        # Method 2: Look for input fields in parent
        inputs = driver.find_elements(By.TAG_NAME, "input")
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        
        print(f"\n[*] Found {len(inputs)} inputs, {len(textareas)} textareas, {len(editables)} editables")
        
        # Filter for visible ones in upper portion
        challenge_inputs = []
        for elem in inputs + textareas + list(editables):
            try:
                if elem.is_displayed():
                    loc = elem.location
                    if loc['y'] < 400:  # Upper portion
                        tag = elem.tag_name
                        cls = elem.get_attribute("class") or ""
                        placeholder = elem.get_attribute("placeholder") or ""
                        print(f"  [UPPER] {tag} at y={loc['y']}: class={cls[:40]}, placeholder={placeholder}")
                        challenge_inputs.append(elem)
            except:
                pass
        
        if challenge_inputs:
            print(f"\n[+] Found {len(challenge_inputs)} potential challenge inputs")
        else:
            print("\n[!] No challenge inputs found - may need to interact with terminal iframe")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
