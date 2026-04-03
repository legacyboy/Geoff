#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Modal Structure Analysis
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Modal Structure")
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
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Click terminal
        print("[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(40)  # Wait longer

        # Analyze modal structure
        print("\n[*] Analyzing modal structure...")
        
        # Get the modal frame
        modal = driver.find_element(By.CSS_SELECTOR, ".modal-frame")
        
        # Get all direct children
        children = modal.find_elements(By.XPATH, "./*")
        print(f"[*] Modal has {len(children)} direct children:")
        
        for i, child in enumerate(children):
            tag = child.tag_name
            cls = child.get_attribute("class") or ""
            print(f"  [{i}] <{tag}> class='{cls}'")
            
            # If it's not iframe, check for inputs
            if tag != "iframe":
                inputs = child.find_elements(By.TAG_NAME, "input")
                if inputs:
                    print(f"      [>] Contains {len(inputs)} inputs!")
                    for j, inp in enumerate(inputs):
                        inp_type = inp.get_attribute("type")
                        visible = inp.is_displayed()
                        print(f"          Input {j}: type={inp_type}, visible={visible}")
        
        # Look for challenge-specific elements
        print("\n[*] Looking for challenge-specific elements...")
        
        # Elements with 'challenge' in class
        challenge_elems = driver.find_elements(By.CSS_SELECTOR, "[class*='challenge']")
        print(f"[*] Found {len(challenge_elems)} elements with 'challenge' in class")
        
        for elem in challenge_elems:
            cls = elem.get_attribute("class")
            tag = elem.tag_name
            print(f"  <{tag}> class='{cls}'")
            
            # Check for inputs inside
            inputs = elem.find_elements(By.TAG_NAME, "input")
            if inputs:
                for inp in inputs:
                    inp_type = inp.get_attribute("type")
                    visible = inp.is_displayed()
                    placeholder = inp.get_attribute("placeholder") or ""
                    print(f"      [>>] Input: type={inp_type}, visible={visible}, placeholder='{placeholder}'")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_modal_structure.png")
        print("\n[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
