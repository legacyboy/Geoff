#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Final
Type 'answer' in the challenge input box
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
    print("SANS HHC 2025 - Terminal 1 Solver")
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
        print("[+] Logged in")

        # Navigate to terminal
        print("\n[*] Going to terminal...")
        driver.get("https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation")
        time.sleep(15)
        
        print(f"[*] URL: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_start.png")
        
        # Look for ALL possible input elements including contenteditable
        print("\n[*] Scanning for inputs...")
        
        # Method 1: All inputs
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] {len(inputs)} input tags")
        
        # Method 2: Textareas (xterm)
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"[*] {len(textareas)} textareas")
        
        # Method 3: Contenteditable divs
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"[*] {len(editables)} contenteditables")
        
        # Try typing in the xterm textarea
        if textareas:
            print("\n[*] Trying xterm textarea...")
            ta = textareas[0]
            
            # Click to focus
            ta.click()
            time.sleep(2)
            
            # Type 'answer' 
            print("[*] Typing 'answer'...")
            ta.send_keys("answer")
            time.sleep(1)
            
            # Submit
            print("[*] Pressing Enter...")
            ta.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Submitted")
        
        # Try contenteditable
        elif editables:
            print("\n[*] Trying contenteditable...")
            ed = editables[0]
            
            ed.click()
            time.sleep(2)
            
            print("[*] Typing 'answer'...")
            ed.send_keys("answer")
            time.sleep(1)
            
            print("[*] Pressing Enter...")
            ed.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Submitted")
        
        # Take result screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_result.png")
        print("\n[+] Screenshot saved: t1_result.png")
        
        # Check result
        text = driver.find_element(By.TAG_NAME, "body").text
        if "2" in text or "completed" in text.lower() or "correct" in text.lower():
            print("[✓] SUCCESS!")
        else:
            print(f"[*] Page text: {text[:300]}")

    except Exception as e:
        print(f"[!] Error: {e}")
        
    finally:
        time.sleep(3)
        driver.quit()


if __name__ == "__main__":
    solve()
