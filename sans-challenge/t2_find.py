#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2 - Find Challenge 2
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
    print("SANS HHC 2025 - Terminal 2 - Find Challenge 2")
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

        # Objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)
        
        # Get full page HTML and text
        print("[*] Getting full page content...")
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        text = driver.find_element(By.TAG_NAME, "body").text
        
        print(f"\n[*] Full page text:\n{text}\n")
        
        # Look for "completed" indicators
        if "completed" in text.lower():
            print("[+] Found 'completed' in text")
        
        # Look for multiple objectives
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"\n[*] Found {len(objectives)} objectives")
        
        for i, obj in enumerate(objectives):
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                classes = obj.get_attribute("class")
                print(f"\n[{i}] {title}")
                print(f"    Classes: {classes}")
                
                # Look for terminal button
                buttons = obj.find_elements(By.TAG_NAME, "button")
                for btn in buttons:
                    btn_text = btn.text
                    print(f"    Button: {btn_text}")
            except:
                pass
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_objectives.png")
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
