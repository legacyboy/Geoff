#!/usr/bin/env python3
"""
SANS HHC 2025 - Check Achievements Page
Verify which terminals/challenges are complete
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def check():
    print("=" * 60)
    print("SANS HHC 2025 - Check Achievements")
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

        # Check Achievements
        print("[*] Checking achievements page...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        # Get page content
        text = driver.find_element(By.TAG_NAME, "body").text
        print(f"\n[*] Achievements page content:\n{text}\n")
        
        # Look for completed challenges/terminals
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        # Check for terminal names
        terminals = ["termOrientation", "It's All About Defang", "defang", "orientation"]
        print("[*] Checking for terminal completions:")
        for term in terminals:
            if term.lower() in text.lower():
                print(f"  [✓] Found: {term}")
        
        # Look for checkmarks or completion indicators
        if "completed" in html.lower() or "fa-check" in html.lower():
            print("\n[✓] Found completion indicators")
        
        # Check objectives page too
        print("\n[*] Checking objectives page...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        obj_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"\n[*] Objectives:\n{obj_text}\n")
        
        # Look for completion in objectives
        if "defang" in obj_text.lower():
            if "completed" in obj_text.lower() or any(mark in obj_text for mark in ['✓', 'check', 'done']):
                print("[✓] Terminal 2 appears complete")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/achievements.png")
        print("\n[+] Screenshot saved: achievements.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    check()
