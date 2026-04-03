#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Using pyautogui for keyboard input
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import pyautogui
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - PyAutoGUI Input")
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
        time.sleep(35)

        # Get iframe location
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            iframe = iframes[0]
            location = iframe.location
            size = iframe.size
            print(f"[*] Iframe location: {location}, size: {size}")
            
            # Calculate center of iframe
            center_x = location['x'] + size['width'] // 2
            center_y = location['y'] + size['height'] // 2
            print(f"[*] Center: ({center_x}, {center_y})")
            
            # Click in the center using pyautogui
            print("\n[*] Clicking terminal with pyautogui...")
            pyautogui.click(center_x, center_y)
            time.sleep(3)
            
            # Type 'answer' using pyautogui
            print("[*] Typing 'answer' with pyautogui...")
            pyautogui.typewrite("answer", interval=0.1)
            time.sleep(2)
            
            # Press Enter
            print("[*] Pressing Enter...")
            pyautogui.keyDown('return')
            pyautogui.keyUp('return')
            time.sleep(5)
            
            print("[+] Input sent")
            
            # Screenshot
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_pyauto_result.png")
            print("[+] Screenshot saved")
        
        # Verify
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
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
        else:
            print("\n[!] Not complete")
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
