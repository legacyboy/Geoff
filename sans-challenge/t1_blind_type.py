#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Blind Type
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
    print("SANS HHC 2025 - Terminal 1 - Blind Type")
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
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(45)

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(15)
        
        # Just focus and type - don't worry about visual feedback
        print("\n[*] Focusing and typing...")
        
        # Click on xterm screen
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        xterm.click()
        time.sleep(3)
        
        # Send keys directly to active element
        print("[*] Sending 'answer'...")
        driver.switch_to.active_element.send_keys("answer")
        time.sleep(2)
        
        print("[*] Sending Enter...")
        driver.switch_to.active_element.send_keys(Keys.RETURN)
        time.sleep(10)
        
        print("[+] Input sent")
        
        # Switch back
        driver.switch_to.default_content()
        
        # Close modal
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(3)
        except:
            pass
        
        # Check status
        print("\n[*] Checking status...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_blind_result.png")
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        text = driver.find_element(By.TAG_NAME, "body").text
        
        print(f"\n[*] Page text:\n{text[:500]}")
        
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check', 'success']):
            print("\n[✓] CHALLENGE COMPLETE!")
        elif "2" in text and "holiday hack" not in text.lower():
            print("\n[✓] Challenge 2 indicator found!")
        else:
            print("\n[!] Not complete - will retry")
            print(f"Classes: {driver.find_element(By.CSS_SELECTOR, '.badge-item.objective').get_attribute('class')}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
