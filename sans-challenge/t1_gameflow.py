#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 via Game Flow
Proper auth flow then interact with terminal
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 (Game Flow)")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 20)

    try:
        # Step 1: Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Enter game
        print("\n[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game")

        # Step 3: CTF Mode
        print("\n[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            print("[+] CTF enabled")
            time.sleep(3)
        except:
            pass

        # Step 4: Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")
        
        # Screenshot before terminal
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before_term.png")

        # Step 5: Click terminal
        print("\n[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        print("[+] Terminal opened")
        time.sleep(20)  # Wait for terminal to fully load
        
        # Screenshot after
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_term.png")
        
        # Step 6: Look for the challenge UI (in parent, not iframe)
        print("\n[*] Looking for challenge input...")
        
        # Check if there's a modal or panel with the challenge
        # Look for text containing ">"
        body_html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        print(f"[*] Body HTML length: {len(body_html)}")
        
        # Look for specific patterns
        if ">" in body_html:
            print("[+] Found '>' in page")
        
        # Try to find any visible text input that might be the challenge box
        all_inputs = driver.find_elements(By.XPATH, "//input[@type='text'] | //input[not(@type)] | //textarea")
        print(f"[*] Found {len(all_inputs)} potential inputs")
        
        for i, inp in enumerate(all_inputs):
            try:
                if inp.is_displayed():
                    print(f"  [{i}] VISIBLE input found!")
                    
                    # Try this one
                    inp.click()
                    time.sleep(1)
                    inp.send_keys("answer")
                    time.sleep(1)
                    inp.send_keys(Keys.RETURN)
                    time.sleep(5)
                    
                    print("[+] Typed 'answer' and submitted")
                    break
            except:
                pass
        
        # Screenshot result
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_final.png")
        print("\n[+] Final screenshot saved")
        
        # Check result
        text = driver.find_element(By.TAG_NAME, "body").text
        success = ['congratulations', 'correct', 'completed', 'success', '2']
        found = [s for s in success if s in text.lower()]
        if found:
            print(f"[✓] SUCCESS! Found: {found}")
        else:
            print(f"[*] No success indicators yet")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        time.sleep(5)
        driver.quit()


if __name__ == "__main__":
    solve()
