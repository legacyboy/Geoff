#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Verify actual status
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
    print("SANS HHC 2025 - Terminal 1 - Status Verification")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game\n")

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Check objectives WITHOUT opening terminal
        print("[*] Checking objectives page...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_status.png")
        print("[+] Screenshot saved: t1_status.png")
        
        # Get full page info
        text = driver.find_element(By.TAG_NAME, "body").text
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        print("\n[*] Page text:")
        print(text)
        
        print("\n[*] Checking for completion indicators:")
        
        # Check for various completion markers
        indicators = {
            'completed': 'completed' in html.lower(),
            'checkmark': 'fa-check' in html.lower() or 'check' in html.lower(),
            'solved': 'solved' in html.lower(),
            'done': 'done' in html.lower(),
            'success': 'success' in html.lower(),
        }
        
        for name, found in indicators.items():
            status = "[✓]" if found else "[ ]"
            print(f"  {status} {name}")
        
        # Check the objective element classes
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"\n[*] Found {len(objectives)} objective elements:")
        for i, obj in enumerate(objectives):
            classes = obj.get_attribute("class")
            print(f"  [{i}] {classes}")
        
        # Check if there's a second challenge listed
        print("\n[*] Looking for challenge #2...")
        if "2" in text or "second" in text.lower():
            print("  [✓] Found '2' or 'second' in text")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
