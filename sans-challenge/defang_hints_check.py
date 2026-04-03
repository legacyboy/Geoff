#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Check Hints
Opens the hint panel to see available hints
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
    print("=" * 70)
    print("SANS HHC 2025 - Checking Hints for Defang Challenge")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login and navigate
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game")

        print("[*] Opening terminal...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    # Click hint button if available
                    try:
                        hint_btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Hint')]")
                        hint_btn.click()
                        print(f"[+] Opened hint for: {title}")
                        time.sleep(5)
                        # Get hint text
                        hint_text = driver.find_element(By.CSS_SELECTOR, ".hint-content, .hint-text").text
                        print(f"[*] Hint: {hint_text}")
                    except:
                        print(f"[!] No hint button found for {title}")
                    
                    # Now open terminal
                    obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]").click()
                    print(f"[+] Opened terminal: {title}")
                    break
            except:
                pass
        
        time.sleep(50)
        print("[+] Terminal loaded")

        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")

        time.sleep(10)
        
        # Check Reference tab for instructions
        print("\n[*] Checking Reference tab for instructions...")
        driver.find_element(By.XPATH, "//button[@data-tab='reference-tab']").click()
        time.sleep(5)
        
        ref_text = driver.execute_script("return document.body.textContent;")
        print(f"\n[*] Reference tab content:\n{ref_text[:2000]}")
        
        # Save screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_reference.png")
        print("\n[+] Screenshot saved")
        
        return True

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
