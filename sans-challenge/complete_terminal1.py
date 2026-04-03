#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Completion
Type 'answer' in the upper input box under 'here:'
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
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

        # Step 2: Direct URL to terminal challenge
        print("\n[*] Navigating directly to terminal challenge...")
        driver.get("https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation")
        time.sleep(10)
        print(f"[*] URL: {driver.current_url}")

        # Screenshot before
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before.png")

        # Step 3: Find the UPPER challenge input box (under 'here:')
        print("\n[*] Looking for challenge input under 'here:'...")
        
        # Get page source to analyze
        page_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"[*] Page text preview:\n{page_text[:500]}\n")
        
        # Look for input elements
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} input elements")
        
        challenge_input = None
        for i, inp in enumerate(inputs):
            try:
                placeholder = inp.get_attribute('placeholder') or ''
                input_type = inp.get_attribute('type') or 'text'
                visible = inp.is_displayed()
                print(f"  [{i}] type={input_type}, placeholder='{placeholder}', visible={visible}")
                
                # The challenge input should be visible and have answer-related placeholder
                if visible and 'answer' in placeholder.lower():
                    challenge_input = inp
                    print(f"  [>] Selected by placeholder match!")
                    break
            except Exception as e:
                pass
        
        # If no specific match, take first visible input
        if not challenge_input:
            for inp in inputs:
                try:
                    if inp.is_displayed():
                        challenge_input = inp
                        print(f"[+] Selected first visible input")
                        break
                except:
                    pass
        
        if challenge_input:
            print("\n[*] Clicking input box...")
            challenge_input.click()
            time.sleep(1)
            
            print("[*] Typing 'answer'...")
            challenge_input.clear()
            challenge_input.send_keys("answer")
            time.sleep(1)
            
            print("[*] Submitting...")
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Submitted!")
        else:
            print("[!] Could not find challenge input")

        # Screenshot after
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after.png")
        
        # Check for completion
        time.sleep(3)
        final_text = driver.find_element(By.TAG_NAME, "body").text
        
        success_words = ['congratulations', 'correct', 'completed', 'success', 'badge', '2', 'next', 'continue']
        found = [w for w in success_words if w in final_text.lower()]
        
        if found:
            print(f"\n[✓] SUCCESS! Indicators found: {found}")
        else:
            print(f"\n[!] No success indicators yet")
            print(f"[*] Page text:\n{final_text[-800:]}")

        # Keep browser open for verification
        print("\n[*] Browser will stay open for 30 seconds...")
        time.sleep(30)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
        try:
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_error.png")
        except:
            pass
        
        input("\nPress Enter to close...")

    finally:
        driver.quit()


if __name__ == "__main__":
    solve()
