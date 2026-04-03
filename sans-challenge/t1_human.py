#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Human-like interaction
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
    print("SANS HHC 2025 - Terminal 1 - Human-like")
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
        time.sleep(3)
        
        # Type slowly like a human
        email = driver.find_element(By.CSS_SELECTOR, "input[type='email']")
        for char in EMAIL:
            email.send_keys(char)
            time.sleep(0.1)
        
        password = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        for char in PASSWORD:
            password.send_keys(char)
            time.sleep(0.1)
        
        password.send_keys(Keys.RETURN)
        time.sleep(8)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(25)

        # CTF Mode
        print("[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(8)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(5)
        except:
            pass

        # Objectives
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(20)

        # Click terminal
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(50)  # Long wait for terminal

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(15)

        # VERY human-like interaction
        print("\n[*] Human-like terminal interaction...")
        
        # 1. Move mouse to terminal area
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        
        # 2. Click and hold briefly
        actions = ActionChains(driver)
        actions.move_to_element(xterm)
        actions.click_and_hold()
        actions.pause(0.5)
        actions.release()
        actions.perform()
        time.sleep(2)
        
        # 3. Type each character with human-like delays
        print("[*] Typing 'answer'...")
        for char in "answer":
            actions = ActionChains(driver)
            actions.send_keys(char)
            actions.perform()
            time.sleep(0.2 + (hash(char) % 100) / 1000)  # Random delay 0.2-0.3s
        
        time.sleep(1)
        
        # 4. Press Enter
        print("[*] Pressing Enter...")
        actions = ActionChains(driver)
        actions.send_keys(Keys.RETURN)
        actions.perform()
        time.sleep(10)
        
        print("[+] Input sent")

        # Switch back
        driver.switch_to.default_content()

        # Close modal
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(5)
        except:
            pass

        # Verify
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
            return True
        else:
            print("\n[!] Not complete")
            print(f"Classes: {driver.find_element(By.CSS_SELECTOR, '.badge-item.objective').get_attribute('class')}")
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
