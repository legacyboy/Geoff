#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Direct URL with full auth
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
    print("SANS HHC 2025 - Terminal 1 - Direct URL")
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

        # Objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)

        # Get iframe src before clicking
        print("[*] Getting iframe URL...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            src = iframes[0].get_attribute("src")
            print(f"[*] Iframe src: {src}")

        # Click terminal to open modal and get the actual iframe
        print("\n[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(25)

        # Now get the iframe src
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            src = iframes[0].get_attribute("src")
            print(f"[+] Iframe src after click: {src}\n")
            
            # Navigate directly to this URL
            print("[*] Navigating to terminal directly...")
            driver.get(src)
            time.sleep(20)
            
            print(f"[*] Current URL: {driver.current_url}")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_direct.png")
            print("[+] Screenshot saved")
            
            # Get page text
            text = driver.find_element(By.TAG_NAME, "body").text
            print(f"\n[*] Body text:\n{text[:500]}")
            
            # Look for challenge prompt
            if "here" in text.lower():
                print("\n[+] Found 'here' in text!")
                
            if ">" in text:
                print("[+] Found '>' in text!")
            
            # Try to type in terminal
            print("\n[*] Attempting to type...")
            textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
            textarea.click()
            time.sleep(2)
            textarea.send_keys("answer")
            time.sleep(1)
            textarea.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Typed 'answer'")
            
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_typed.png")
            print("[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        time.sleep(5)
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
