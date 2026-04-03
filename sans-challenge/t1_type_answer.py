#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Type 'answer' next to >
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
    print("SANS HHC 2025 - Terminal 1 - Type 'answer'")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 20)

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
        print("[+] In game")

        # CTF Mode
        print("\n[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            print("[+] CTF enabled")
            time.sleep(3)
        except:
            pass

        # Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")
        
        # Screenshot before
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before.png")

        # Click terminal
        print("\n[*] Clicking terminal button...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        print("[+] Terminal opened")
        time.sleep(20)
        
        # Screenshot after open
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_terminal_open.png")
        
        # Look for the challenge input - it's NOT in the iframe
        # It's on the parent page, likely rendered by React
        print("\n[*] Looking for challenge input...")
        
        # Switch to default content first
        driver.switch_to.default_content()
        
        # Look for ANY input that's visible
        all_inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Total inputs on page: {len(all_inputs)}")
        
        challenge_input = None
        for inp in all_inputs:
            try:
                inp_type = inp.get_attribute("type") or "text"
                visible = inp.is_displayed()
                placeholder = inp.get_attribute("placeholder") or ""
                
                if visible and inp_type == "text":
                    print(f"[+] Found visible text input! placeholder='{placeholder}'")
                    challenge_input = inp
                    break
            except:
                pass
        
        if challenge_input:
            print("\n[*] Clicking input...")
            challenge_input.click()
            time.sleep(2)
            
            print("[*] Typing 'answer'...")
            challenge_input.send_keys("answer")
            time.sleep(1)
            
            print("[*] Pressing Enter...")
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Submitted!")
        else:
            print("\n[!] No challenge input found in parent")
            
            # Maybe it's a contenteditable div?
            print("[*] Looking for contenteditable...")
            editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
            print(f"[*] Found {len(editables)} contenteditables")
            
            for ed in editables:
                try:
                    if ed.is_displayed():
                        cls = ed.get_attribute("class") or ""
                        if "xterm" not in cls.lower():
                            print(f"[+] Found non-xterm contenteditable!")
                            ed.click()
                            time.sleep(2)
                            ed.send_keys("answer")
                            time.sleep(1)
                            ed.send_keys(Keys.RETURN)
                            time.sleep(5)
                            print("[+] Submitted!")
                            break
                except:
                    pass
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_done.png")
        print("\n[+] Screenshot saved: t1_done.png")
        
        # Check for success
        text = driver.find_element(By.TAG_NAME, "body").text
        if "2" in text:
            print("[✓] SUCCESS - Challenge 2 indicator found!")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        time.sleep(5)
        driver.quit()


if __name__ == "__main__":
    solve()
