#!/usr/bin/env python3
"""
SANS HHC 2025 - Click "Play Now!" to enter game
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
    print("="*60)
    print("SANS HHC 2025 - Play Now Automation")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Step 1: Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print(f"[+] Logged in: {driver.current_url}")
        
        # Step 2: Click "Play Now!"
        print("\n[*] Looking for 'Play Now!' button...")
        time.sleep(3)
        
        # Try multiple selectors for Play Now button
        play_now_selectors = [
            "//button[contains(text(), 'Play Now')]",
            "//a[contains(text(), 'Play Now')]",
            "//*[contains(text(), 'Play Now')]",
            "[value*='Play Now']",
            "[class*='play']",
            "button:contains('Play')",
            "a:contains('Play')"
        ]
        
        play_now = None
        for selector in play_now_selectors:
            try:
                if selector.startswith("//"):
                    play_now = driver.find_element(By.XPATH, selector)
                else:
                    play_now = driver.find_element(By.CSS_SELECTOR, selector)
                
                if play_now:
                    print(f"[+] Found 'Play Now!' button: {selector}")
                    break
            except:
                continue
        
        if play_now:
            print("[*] Clicking 'Play Now!'...")
            try:
                play_now.click()
            except:
                driver.execute_script("arguments[0].click();", play_now)
            
            time.sleep(10)  # Wait for game to load
            print(f"[+] After Play Now: {driver.current_url}")
        else:
            print("[!] Could not find Play Now button")
            # Try navigating directly
            driver.get("https://2025.holidayhackchallenge.com/")
            time.sleep(10)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_play_now.png")
        print("[+] Screenshot saved")
        
        # Step 3: Click Objectives
        print("\n[*] Looking for Objectives...")
        time.sleep(5)
        
        try:
            objectives = driver.find_element(By.XPATH, "//*[contains(text(), 'Objectives')]")
            print("[+] Found Objectives")
            objectives.click()
            time.sleep(3)
        except:
            print("[!] Could not find Objectives")
        
        # Step 4: Find and click terminal
        print("\n[*] Looking for terminal...")
        terminals = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal']")
        print(f"[+] Found {len(terminals)} terminal elements")
        
        if terminals:
            # Click first terminal
            driver.execute_script("arguments[0].scrollIntoView(true);", terminals[0])
            time.sleep(1)
            driver.execute_script("arguments[0].click();", terminals[0])
            print("[*] Clicked terminal")
            time.sleep(10)
        
        # Step 5: Solve if terminal opened
        if "wetty" in driver.current_url:
            print("\n[*] Terminal open! Solving...")
            time.sleep(10)
            
            textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
            textarea.click()
            time.sleep(1)
            textarea.send_keys("answer")
            time.sleep(1)
            textarea.send_keys(Keys.RETURN)
            time.sleep(5)
            print("[+] Submitted answer")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_result.png")
        print("\n[+] Done")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()

if __name__ == "__main__":
    solve()
