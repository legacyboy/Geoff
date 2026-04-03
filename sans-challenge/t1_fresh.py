#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Fresh Start with Credentials
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Fresh Start")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Step 1: Login
        print("[*] Logging in with provided credentials...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        email_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='email']")))
        email_field.send_keys(EMAIL)
        print("[+] Email entered")
        
        pass_field = driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        pass_field.send_keys(PASSWORD + Keys.RETURN)
        print("[+] Password entered, submitting...")
        
        time.sleep(5)
        print("[+] Logged in\n")

        # Step 2: Enter game
        print("[*] Entering game world...")
        play_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Play Now')]")))
        play_btn.click()
        time.sleep(20)  # Wait for game to load
        print("[+] In game\n")

        # Step 3: Enable CTF Mode
        print("[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            ctf_btn = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            ctf_btn.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            print("[!] CTF button not found or already enabled")

        # Step 4: Go to Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)
        print("[+] Objectives loaded")
        
        # Take screenshot before
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before_terminal.png")

        # Step 5: Click terminal button
        print("\n[*] Clicking 'Open Terminal' button...")
        term_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
        term_btn.click()
        print("[+] Terminal button clicked")
        time.sleep(30)  # Wait for terminal to fully load

        # Step 6: Find the challenge input
        print("\n[*] Searching for challenge input...")
        
        # First, check if there's a challenge UI outside the iframe
        driver.switch_to.default_content()
        
        # Look for any text input that's not in the iframe
        all_inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(all_inputs)} inputs in parent window")
        
        challenge_input = None
        for inp in all_inputs:
            try:
                inp_type = inp.get_attribute("type") or "text"
                visible = inp.is_displayed()
                placeholder = inp.get_attribute("placeholder") or ""
                
                if visible and inp_type == "text":
                    print(f"[+] Found visible text input: placeholder='{placeholder}'")
                    challenge_input = inp
                    break
            except:
                pass
        
        # If no input found in parent, look for contenteditable
        if not challenge_input:
            editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
            print(f"[*] Found {len(editables)} contenteditables in parent")
            for ed in editables:
                try:
                    if ed.is_displayed():
                        cls = ed.get_attribute("class") or ""
                        if "xterm" not in cls.lower():
                            print(f"[+] Found non-xterm contenteditable")
                            challenge_input = ed
                            break
                except:
                    pass
        
        # If still not found, try inside iframe
        if not challenge_input:
            print("\n[*] Looking inside iframe...")
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            if iframes:
                driver.switch_to.frame(iframes[0])
                print("[+] Switched to iframe")
                
                # Look for textarea (xterm)
                textareas = driver.find_elements(By.TAG_NAME, "textarea")
                print(f"[*] Found {len(textareas)} textareas in iframe")
                
                for ta in textareas:
                    try:
                        if ta.is_displayed():
                            print("[+] Found textarea in iframe")
                            challenge_input = ta
                            break
                    except:
                        pass
        
        # Step 7: Type answer
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
            print("\n[!] Could not find challenge input!")

        # Step 8: Verify completion
        print("\n[*] Verifying completion...")
        driver.switch_to.default_content()
        
        # Close modal if open
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(3)
            print("[+] Closed terminal modal")
        except:
            pass
        
        # Refresh objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        # Take screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_submit.png")
        
        # Check for completion indicators
        text = driver.find_element(By.TAG_NAME, "body").text
        if any(k in text.lower() for k in ['completed', 'done', 'check', '✓']):
            print("[✓] CHALLENGE COMPLETED!")
        elif "2" in text:
            print("[✓] Challenge 2 available - Terminal 1 complete!")
        else:
            print("[!] Challenge may not be complete yet")
            print(f"[*] Page text:\n{text[:500]}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_error.png")

    finally:
        time.sleep(5)
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
