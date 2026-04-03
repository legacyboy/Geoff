#!/usr/bin/env python3
"""
SANS HHC 2025 - Enable CTF Mode First
Gear -> Settings -> CTF Style -> Objectives -> Terminal
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
    print("="*60)
    print("SANS HHC 2025 - CTF Mode Solver")
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
        
        # Step 2: Click Play Now
        print("\n[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print(f"[+] Game loaded: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_loaded.png")
        
        # Step 3: Click Settings/GEAR icon (top right)
        print("\n[*] Step 3: Clicking Settings icon...")
        time.sleep(5)
        
        # Settings icon - look for text "Settings"
        settings_clicked = False
        
        # Method 1: Find by text "Settings"
        try:
            settings_btn = driver.find_element(By.XPATH, "//*[contains(text(), 'Settings')]")
            print("[+] Found Settings button by text")
            driver.execute_script("arguments[0].click();", settings_btn)
            settings_clicked = True
        except:
            pass
        
        # Method 2: Find by aria-label
        if not settings_clicked:
            try:
                settings_btn = driver.find_element(By.CSS_SELECTOR, "[aria-label='Settings'], [title='Settings']")
                print("[+] Found Settings by aria-label/title")
                driver.execute_script("arguments[0].click();", settings_btn)
                settings_clicked = True
            except:
                pass
        
        # Method 3: Click top-right area
        if not settings_clicked:
            print("[*] Trying coordinate click for Settings...")
            actions = ActionChains(driver)
            actions.move_by_offset(1300, 50)  # Top right
            actions.click()
            actions.perform()
            settings_clicked = True
        
        if gear_clicked:
            print("[+] Clicked gear icon")
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_gear.png")
        
        # Step 4: Click Settings
        print("\n[*] Step 4: Clicking Settings...")
        time.sleep(2)
        
        settings_clicked = False
        try:
            settings = driver.find_element(By.XPATH, "//*[contains(text(), 'Settings')]")
            driver.execute_script("arguments[0].click();", settings)
            settings_clicked = True
            print("[+] Clicked Settings")
        except:
            pass
        
        if settings_clicked:
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/settings_open.png")
        
        # Step 5: Enable CTF Style
        print("\n[*] Step 5: Enabling CTF Style...")
        time.sleep(2)
        
        ctf_clicked = False
        try:
            ctf = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style') or contains(text(), 'CTF')]")
            driver.execute_script("arguments[0].click();", ctf)
            ctf_clicked = True
            print("[+] Enabled CTF Style")
        except:
            print("[!] Could not find CTF Style button")
        
        if ctf_clicked:
            time.sleep(5)
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/ctf_enabled.png")
        
        # Step 6: Click Objectives
        print("\n[*] Step 6: Opening Objectives...")
        time.sleep(3)
        
        try:
            objectives = driver.find_element(By.XPATH, "//*[contains(text(), 'Objectives')]")
            driver.execute_script("arguments[0].click();", objectives)
            print("[+] Opened Objectives")
            time.sleep(5)
        except:
            print("[!] Could not find Objectives")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_view.png")
        
        # Step 7: Click termOrientation terminal
        print("\n[*] Step 7: Clicking termOrientation terminal...")
        time.sleep(3)
        
        try:
            term = driver.find_element(By.XPATH, "//*[contains(text(), 'termOrientation')]")
            driver.execute_script("arguments[0].click();", term)
            print("[+] Clicked terminal")
            time.sleep(15)  # Wait for terminal to load
        except:
            print("[!] Could not find termOrientation")
        
        # Step 8: Solve if terminal opened
        if "wetty" in driver.current_url:
            print("\n[*] Step 8: Solving challenge...")
            time.sleep(10)
            
            textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
            textarea.click()
            time.sleep(2)
            textarea.send_keys("answer")
            time.sleep(2)
            textarea.send_keys(Keys.RETURN)
            time.sleep(10)
            
            print("[+] Submitted answer")
            
            # Check for success
            text = driver.find_element(By.TAG_NAME, "body").text
            if any(word in text.lower() for word in ['congratulations', 'completed', 'success', 'badge']):
                print("\n[✓] CHALLENGE SOLVED!")
            else:
                print("\n[?] Check screenshot for result")
        else:
            print(f"\n[!] Terminal not opened. URL: {driver.current_url}")
        
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
