#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Parent Modal Input
The challenge input is ABOVE the terminal iframe, not inside it
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
    print("SANS HHC 2025 - Terminal 1 - Parent Modal Input")
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
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Click terminal
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(35)
        
        print("[+] Terminal modal opened")

        # DO NOT switch to iframe - look for input in PARENT
        print("\n[*] Looking for challenge input in parent modal...")
        
        # Look for text input or textarea in the modal-frame (outside iframe)
        # The input should be near the text "Enter the answer here:"
        
        # Method 1: Find by placeholder or nearby text
        try:
            # Look for input near "Enter the answer here"
            challenge_input = driver.find_element(By.XPATH, "//input[contains(@placeholder, 'answer') or contains(@placeholder, 'here')]")
            print("[+] Found input by placeholder")
        except:
            try:
                # Look for any visible text input in modal
                inputs = driver.find_elements(By.TAG_NAME, "input")
                challenge_input = None
                for inp in inputs:
                    try:
                        # Check if it's visible and not the iframe
                        if inp.is_displayed() and inp.get_attribute("type") == "text":
                            # Make sure it's not inside the iframe (check location)
                            location = inp.location
                            if location['y'] < 400:  # Should be in upper part of modal
                                challenge_input = inp
                                print(f"[+] Found input at y={location['y']}")
                                break
                    except:
                        pass
            except:
                challenge_input = None
        
        # Method 2: Look for contenteditable div
        if not challenge_input:
            try:
                editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
                for ed in editables:
                    try:
                        if ed.is_displayed():
                            # Check if it's outside iframe
                            location = ed.location
                            if location['y'] < 400:
                                challenge_input = ed
                                print("[+] Found contenteditable")
                                break
                    except:
                        pass
            except:
                pass
        
        # Method 3: Look for textarea
        if not challenge_input:
            try:
                textareas = driver.find_elements(By.TAG_NAME, "textarea")
                for ta in textareas:
                    try:
                        if ta.is_displayed():
                            location = ta.location
                            if location['y'] < 400:
                                challenge_input = ta
                                print("[+] Found textarea")
                                break
                    except:
                        pass
            except:
                pass
        
        if challenge_input:
            print("\n[*] Typing 'answer' in challenge input...")
            challenge_input.click()
            time.sleep(2)
            challenge_input.send_keys("answer")
            time.sleep(1)
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(5)
            print("[+] Submitted!")
        else:
            print("\n[!] Could not find challenge input")
            
            # Try clicking where the > should be (upper part of modal)
            print("[*] Trying to click near > position...")
            modal = driver.find_element(By.CSS_SELECTOR, ".modal-frame")
            location = modal.location
            size = modal.size
            
            # Click in upper portion of modal (above iframe)
            click_x = location['x'] + 200
            click_y = location['y'] + 100
            
            actions = ActionChains(driver)
            actions.move_by_offset(click_x, click_y)
            actions.click()
            actions.send_keys("answer")
            actions.send_keys(Keys.RETURN)
            actions.perform()
            time.sleep(5)
            print("[+] Attempted click and type")

        # Close modal
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        # Verify
        print("\n[*] Verifying completion...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
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
