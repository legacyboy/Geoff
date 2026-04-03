#!/usr/bin/env python3
"""
SANS HHC 2025 - Direct URL Navigation
Skip UI clicks, go directly to settings and objectives via URL params
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
    print("SANS HHC 2025 - Direct URL Navigation")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")
        
        # Step 2: Enter game
        print("\n[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] Game loaded")
        
        # Step 3: Go DIRECTLY to settings via URL
        print("\n[*] Step 3: Navigating to Settings...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        print("[+] Settings page loaded")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/settings_page.png")
        
        # Step 4: Click CTF Style button
        print("\n[*] Step 4: Enabling CTF Style...")
        time.sleep(3)
        
        ctf_clicked = False
        try:
            # Look for CTF Style button
            ctf_btn = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style') or contains(text(), 'CTF')]")
            print("[+] Found CTF Style button")
            driver.execute_script("arguments[0].click();", ctf_btn)
            ctf_clicked = True
            print("[+] Clicked CTF Style")
        except:
            print("[!] Could not find CTF Style by text, trying other methods...")
            
            # Try finding by class or button type
            try:
                buttons = driver.find_elements(By.TAG_NAME, "button")
                for btn in buttons:
                    text = btn.text
                    if 'ctf' in text.lower() or 'style' in text.lower():
                        print(f"[+] Found button: {text}")
                        driver.execute_script("arguments[0].click();", btn)
                        ctf_clicked = True
                        break
            except:
                pass
        
        if ctf_clicked:
            time.sleep(5)
            print("[+] CTF Style enabled")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/ctf_enabled.png")
        
        # Step 5: Go DIRECTLY to objectives
        print("\n[*] Step 5: Navigating to Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives page loaded")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_page.png")
        
        # Step 6: Click termOrientation terminal
        print("\n[*] Step 6: Clicking termOrientation terminal...")
        time.sleep(3)
        
        try:
            term = driver.find_element(By.XPATH, "//*[contains(text(), 'termOrientation')]")
            print("[+] Found termOrientation")
            driver.execute_script("arguments[0].click();", term)
            time.sleep(15)  # Wait for terminal to load
        except:
            print("[!] Could not find termOrientation by text")
            
            # Try by class
            try:
                term = driver.find_element(By.CSS_SELECTOR, "[class*='termOrientation']")
                print("[+] Found termOrientation by class")
                driver.execute_script("arguments[0].click();", term)
                time.sleep(15)
            except:
                print("[!] Could not find termOrientation")
        
        print(f"[*] After terminal click: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_terminal_click.png")
        
        # Step 7: Solve if terminal opened
        if "wetty" in driver.current_url:
            print("\n[*] Step 7: Solving challenge...")
            time.sleep(10)
            
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                print("[+] Found terminal textarea")
                
                textarea.click()
                time.sleep(2)
                print("[*] Typing 'answer'...")
                textarea.send_keys("answer")
                time.sleep(2)
                print("[*] Submitting...")
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)
                
                print("[+] Answer submitted")
                
                # Check for success
                text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']):
                    print("\n[✓] CHALLENGE SOLVED!")
                else:
                    print("\n[!] Check screenshot for result")
                    
            except Exception as e:
                print(f"[!] Error solving: {e}")
        else:
            print(f"\n[!] Terminal not opened. Current URL: {driver.current_url}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_result.png")
        print("\n[+] Final screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Done")

if __name__ == "__main__":
    solve()
