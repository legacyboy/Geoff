#!/usr/bin/env python3
"""
SANS HHC 2025 - Check BOTH Objectives and Achievements for Defang completion
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os
import sys

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def check():
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    complete = False

    try:
        # Login
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)

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

        # Check Objectives for completion
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        objectives_html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        # Check if defang objective has completed class or checkmark
        if "defang" in objectives_html.lower():
            # Look for completed indicators in the defang section
            if "completed" in objectives_html.lower() or "fa-check" in objectives_html.lower():
                print("✓ Defang complete in objectives")
                complete = True
            else:
                print("✗ Defang pending in objectives")
        
        # Check Achievements
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        achievements_text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in achievements_text.lower() or "its all about" in achievements_text.lower():
            print("✓ Defang found in achievements")
            complete = True
        else:
            print("✗ Defang NOT in achievements")

        return complete

    except Exception as e:
        print(f"[!] Error: {e}")
        return False

    finally:
        driver.quit()


if __name__ == "__main__":
    if check():
        sys.exit(0)  # Success
    else:
        sys.exit(1)  # Not complete
