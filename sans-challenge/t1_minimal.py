#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Minimal approach
Just type answer at the prompt
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
    print("SANS HHC 2025 - Terminal 1 - Minimal")
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
        
        # Don't wait - immediately try to interact
        print("[*] Waiting 15 seconds...")
        time.sleep(15)

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
        
        print("[*] Typing immediately...")
        
        # Just send keys to the active element (the iframe body)
        actions = ActionChains(driver)
        actions.send_keys("answer")
        actions.perform()
        time.sleep(1)
        
        actions = ActionChains(driver)
        actions.send_keys(Keys.RETURN)
        actions.perform()
        time.sleep(10)
        
        print("[+] Typed")
        
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
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
        else:
            print("\n[!] Not complete")
            print(f"Text: {text[:300]}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
