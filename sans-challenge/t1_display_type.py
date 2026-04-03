#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Type using display coordinates
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import subprocess
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Display Type")
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
        time.sleep(10)

        # Click terminal
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(35)

        # Get iframe location on screen
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            iframe = iframes[0]
            location = iframe.location
            size = iframe.size
            
            # Calculate position to click (right of > prompt)
            # Terminal is typically in center, > is on left side
            click_x = location['x'] + 150  # 150px from left edge of iframe
            click_y = location['y'] + size['height'] // 2  # Middle height
            
            print(f"[*] Iframe at: ({location['x']}, {location['y']}), size: {size}")
            print(f"[*] Will click at: ({click_x}, {click_y})")
            
            # Click using xdotool
            subprocess.run(['xdotool', 'mousemove', str(click_x), str(click_y), 'click', '1'], check=False)
            time.sleep(2)
            print("[+] Clicked on terminal")
            
            # Type 'answer' using xdotool
            subprocess.run(['xdotool', 'type', 'answer'], check=False)
            time.sleep(1)
            print("[+] Typed 'answer'")
            
            # Press Enter
            subprocess.run(['xdotool', 'key', 'Return'], check=False)
            time.sleep(5)
            print("[+] Pressed Enter")
        
        # Close modal
        driver.switch_to.default_content()
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass
        
        # Verify
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
            return True
        else:
            print("\n[!] Not complete")
            return False

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
