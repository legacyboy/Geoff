#!/usr/bin/env python3
"""
SANS HHC 2025 - Verify Completion via Achievements
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
    print("SANS HHC 2025 - Verify via Achievements")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login
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
        print("[*] Checking achievements...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        print(f"\n[*] Achievements:\n{text}\n")
        
        # Look for specific completions
        if "holiday hack orientation" in text.lower():
            print("[✓] Terminal 1: Holiday Hack Orientation - COMPLETE")
        
        if "defang" in text.lower():
            print("[✓] Terminal 2: It's All About Defang - COMPLETE")
        elif "its all about" in text.lower():
            print("[✓] Terminal 2: It's All About Defang - COMPLETE")

    except Exception as e:
        print(f"[!] Error: {e}")

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    check()
