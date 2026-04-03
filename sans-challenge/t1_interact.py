#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Interact and find challenge UI
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
    print("SANS HHC 2025 - Terminal 1 - Interact and Find UI")
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
        print("[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(35)

        # Screenshot before interaction
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before_interact.png")
        
        # Try to interact with iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            print("[*] Switching to iframe...")
            driver.switch_to.frame(iframes[0])
            
            # Try clicking on terminal
            print("[*] Clicking on terminal screen...")
            try:
                xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
                xterm.click()
                time.sleep(5)
                print("[+] Clicked")
            except:
                pass
            
            # Try typing something to see what happens
            print("[*] Typing 'ls' to see terminal response...")
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
                textarea.send_keys("ls")
                time.sleep(2)
                textarea.send_keys(Keys.RETURN)
                time.sleep(5)
                print("[+] Typed 'ls'")
            except Exception as e:
                print(f"[!] Error typing: {e}")
            
            # Get HTML after interaction
            html = driver.page_source
            with open("/home/claw/.openclaw/workspace/sans-challenge/t1_after_interact.html", "w") as f:
                f.write(html)
            
            # Switch back
            driver.switch_to.default_content()
        
        # Screenshot after
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_interact.png")
        
        # Check for challenge UI in parent
        print("\n[*] Checking for challenge UI in parent...")
        body_text = driver.find_element(By.TAG_NAME, "body").text
        if "here" in body_text.lower():
            print("[+] Found 'here' in body text!")
            idx = body_text.lower().find("here")
            print(f"Context: ...{body_text[max(0,idx-50):idx+100]}...")
        
        if ">" in body_text:
            print("[+] Found '>' in body text!")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
