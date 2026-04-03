#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Solver
Types 'answer' in the upper input box under 'here:'
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
    print("SANS HHC 2025 - Terminal 1 (termOrientation)")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

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
        print("[+] In game world")

        # Step 3: Enable CTF Mode
        print("\n[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            ctf = wait.until(lambda d: d.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]"))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            pass

        # Step 4: Open Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        # Step 5: Click terminal button
        print("\n[*] Clicking terminal button...")
        try:
            term_btn = wait.until(lambda d: d.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]"))
            term_btn.click()
            print("[+] Terminal button clicked")
            time.sleep(20)
        except Exception as e:
            print(f"[!] Terminal button error: {e}")

        # Step 6: Switch to iframe
        print("\n[*] Switching to iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")
        
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        time.sleep(15)  # Wait for terminal to load

        # Step 7: Find and fill the challenge input
        print("\n[*] Finding challenge input under 'here:'...")
        
        # Get all inputs and their details
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} input elements")
        
        challenge_input = None
        for inp in inputs:
            try:
                inp_type = inp.get_attribute("type") or "text"
                inp_class = inp.get_attribute("class") or ""
                placeholder = inp.get_attribute("placeholder") or ""
                visible = inp.is_displayed()
                
                print(f"  Input: type={inp_type}, class={inp_class}, placeholder='{placeholder}', visible={visible}")
                
                # Accept any visible input that's not a button/submit
                if visible and inp_type not in ["button", "submit", "hidden", "checkbox"]:
                    challenge_input = inp
                    print(f"  [+] Selected this input!")
                    break
            except Exception as e:
                pass
        
        if challenge_input:
            print("\n[*] Clicking input...")
            challenge_input.click()
            time.sleep(1)
            
            print("[*] Typing 'answer'...")
            challenge_input.send_keys("answer")
            time.sleep(1)
            
            print("[*] Submitting with Enter...")
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Submitted!")
            
            # Wait and check for completion
            time.sleep(5)
            
            # Take screenshot
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_result.png")
            print("[+] Screenshot saved to t1_result.png")
            
            # Check page for success indicators
            body_text = driver.find_element(By.TAG_NAME, "body").text
            
            success = ['congratulations', 'correct', 'completed', 'success', 'badge', '2', 'next']
            found = [s for s in success if s in body_text.lower()]
            
            if found:
                print(f"\n[✓] SUCCESS! Found indicators: {found}")
            else:
                print(f"\n[!] No clear success indicators yet")
                print(f"[*] Page text (last 500 chars): {body_text[-500:]}")
        else:
            print("\n[!] Could not find challenge input")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_noinput.png")

        # Wait to see result
        print("\n[*] Waiting 10 seconds for result...")
        time.sleep(10)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
