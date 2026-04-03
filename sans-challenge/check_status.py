#!/usr/bin/env python3
"""
SANS HHC 2025 - Check Objective Status
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
    print("SANS HHC 2025 - Check Status")
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

        # Check Objectives
        print("[*] Checking objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        # Find all objective elements
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"\n[*] Found {len(objectives)} objectives:\n")
        
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                classes = obj.get_attribute("class")
                
                # Check if completed
                is_completed = any(k in classes.lower() for k in ['completed', 'solved', 'done'])
                has_check = 'fa-check' in obj.get_attribute("innerHTML").lower()
                
                status = "✅ COMPLETE" if (is_completed or has_check) else "⏳ PENDING"
                print(f"  {status}: {title}")
                print(f"      Classes: {classes}")
                
                # Check for terminal button
                try:
                    btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Terminal')]")
                    print(f"      Button: {btn.text}")
                except:
                    pass
                print()
                
            except Exception as e:
                print(f"  [!] Error reading objective: {e}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/status_check.png")
        print("[+] Screenshot saved: status_check.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("[+] Done")


if __name__ == "__main__":
    check()
