#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Blind Loop
Keep trying until complete
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


def check_complete(driver):
    """Check if terminal 1 is complete"""
    try:
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(8)
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        # Check for completion indicators
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check', 'success']):
            return True
        
        # Check objective classes
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        for obj in objectives:
            classes = obj.get_attribute("class")
            if any(k in classes.lower() for k in ['completed', 'solved', 'done']):
                return True
        
        return False
    except:
        return False


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Blind Loop")
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

        # Check initial status
        if check_complete(driver):
            print("[✓] Already complete!")
            return

        # Try multiple times
        for attempt in range(1, 11):
            print(f"\n{'='*60}")
            print(f"ATTEMPT {attempt}/10")
            print(f"{'='*60}")
            
            # Open terminal
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(10)
            driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
            time.sleep(20)  # Shorter wait
            
            # Switch to iframe
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            if iframes:
                driver.switch_to.frame(iframes[0])
            
            # Type immediately
            print("[*] Typing 'answer'...")
            actions = ActionChains(driver)
            actions.send_keys("answer")
            actions.perform()
            time.sleep(1)
            
            actions = ActionChains(driver)
            actions.send_keys(Keys.RETURN)
            actions.perform()
            time.sleep(5)
            
            print("[+] Typed")
            
            # Switch back
            driver.switch_to.default_content()
            
            # Close modal
            try:
                driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
                time.sleep(2)
            except:
                pass
            
            # Check if complete
            if check_complete(driver):
                print("\n" + "="*60)
                print("[✓✓✓] CHALLENGE COMPLETE!")
                print("="*60)
                break
            else:
                print("[!] Not complete yet")
        
        # Final check
        print("\n[*] Final status check...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_final.png")
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        text = driver.find_element(By.TAG_NAME, "body").text
        
        print(f"\n[*] Final page text:\n{text[:500]}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
