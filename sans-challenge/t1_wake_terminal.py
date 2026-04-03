#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Wake up terminal
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
    print("SANS HHC 2025 - Terminal 1 - Wake Terminal")
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
        time.sleep(40)

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(15)
        
        # Screenshot initial state
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_initial.png")
        print("[+] Initial screenshot")
        
        # Click in terminal to focus
        print("\n[*] Focusing terminal...")
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        
        actions = ActionChains(driver)
        actions.move_to_element(xterm)
        actions.click()
        actions.perform()
        time.sleep(3)
        
        # Press space to wake up
        print("[*] Pressing space to wake terminal...")
        actions = ActionChains(driver)
        actions.send_keys(Keys.SPACE)
        actions.perform()
        time.sleep(5)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_wake.png")
        print("[+] Screenshot after wake attempt")
        
        # Try Enter
        print("\n[*] Pressing Enter...")
        actions = ActionChains(driver)
        actions.send_keys(Keys.RETURN)
        actions.perform()
        time.sleep(5)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_enter.png")
        print("[+] Screenshot after Enter")
        
        # Now try typing
        print("\n[*] Typing 'answer'...")
        actions = ActionChains(driver)
        actions.send_keys("answer")
        actions.perform()
        time.sleep(2)
        
        actions = ActionChains(driver)
        actions.send_keys(Keys.RETURN)
        actions.perform()
        time.sleep(5)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_final.png")
        print("[+] Final screenshot")
        
        # Verify
        driver.switch_to.default_content()
        
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(3)
        except:
            pass
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
        else:
            print("\n[!] Not complete")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
