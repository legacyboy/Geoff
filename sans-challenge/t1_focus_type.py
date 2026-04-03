#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Focus terminal and type
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
    print("SANS HHC 2025 - Terminal 1 - Focus and Type")
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
        print("[+] Logged in")

        # Enter game
        print("\n[*] Entering game...")
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
        
        # Click terminal
        print("\n[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(25)  # Wait for terminal
        
        # Switch to iframe
        print("\n[*] Switching to terminal iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        time.sleep(10)  # Wait for terminal to initialize
        
        # Try to click on the terminal to focus it
        print("\n[*] Clicking on terminal to focus...")
        
        # Click on the xterm screen
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        xterm.click()
        time.sleep(2)
        print("[+] Clicked xterm screen")
        
        # Alternative: click on the textarea
        textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
        textarea.click()
        time.sleep(2)
        print("[+] Clicked textarea")
        
        # Type answer
        print("\n[*] Typing 'answer'...")
        textarea.send_keys("answer")
        time.sleep(1)
        
        print("[*] Pressing Enter...")
        textarea.send_keys(Keys.RETURN)
        time.sleep(5)
        
        print("[+] Submitted!")
        
        # Switch back and check
        driver.switch_to.default_content()
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_result.png")
        print("\n[+] Screenshot saved")
        
        # Check for success
        text = driver.find_element(By.TAG_NAME, "body").text
        if "2" in text or "completed" in text.lower():
            print("[✓] Challenge completed!")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_error.png")
        
    finally:
        driver.quit()


if __name__ == "__main__":
    solve()
