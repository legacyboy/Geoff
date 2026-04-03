#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Check status without terminal open
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
    print("SANS HHC 2025 - Terminal 1 - Status Check")
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
        time.sleep(15)

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Check objective page WITHOUT terminal open
        print("[*] Checking objectives page (no terminal)...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        # Get the full text
        text = driver.find_element(By.TAG_NAME, "body").text
        print("\n[*] Full page text:")
        print(text)
        
        # Save screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_status_check.png")
        print("\n[+] Screenshot saved")
        
        # Look for challenge indicators
        print("\n[*] Checking for completion indicators...")
        
        # Check for checkmarks, completed status, etc
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        if "completed" in html.lower():
            print("[✓] 'completed' found in HTML")
        if "check" in html.lower():
            print("[✓] 'check' found in HTML")
        if 'fa-check' in html.lower():
            print("[✓] FontAwesome checkmark found")
        if 'success' in html.lower():
            print("[✓] 'success' found in HTML")
            
        # Check the objective div classes
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"\n[*] Found {len(objectives)} objective elements")
        
        for i, obj in enumerate(objectives):
            classes = obj.get_attribute("class")
            print(f"  [{i}] Classes: {classes}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
