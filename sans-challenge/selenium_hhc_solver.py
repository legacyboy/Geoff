#!/usr/bin/env python3
"""
SANS HHC 2025 - Full GUI Browser Automation
Uses Selenium with Firefox to interact with the game properly
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
import time

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def solve_hhc():
    print("="*60)
    print("SANS HHC 2025 - Full GUI Automation")
    print("="*60 + "\n")
    
    # Set up Firefox options
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    # Don't run headless - we need the GUI for proper session handling
    
    # Set display
    import os
    os.environ['DISPLAY'] = ':0'
    
    print("[*] Launching Firefox...")
    driver = webdriver.Firefox(options=options)
    
    try:
        # Step 1: Login
        print("[*] Navigating to login page...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        print("[*] Entering credentials...")
        # Find email field
        email_field = driver.find_element(By.NAME, "email") or driver.find_element(By.ID, "email") or driver.find_element(By.CSS_SELECTOR, "input[type='email']")
        email_field.clear()
        email_field.send_keys(EMAIL)
        
        # Find password field
        password_field = driver.find_element(By.NAME, "password") or driver.find_element(By.ID, "password") or driver.find_element(By.CSS_SELECTOR, "input[type='password']")
        password_field.clear()
        password_field.send_keys(PASSWORD)
        
        # Submit login
        print("[*] Submitting login...")
        password_field.send_keys(Keys.RETURN)
        time.sleep(5)
        
        print(f"[+] Current URL: {driver.current_url}")
        
        # Step 2: Navigate to main game
        print("\n[*] Navigating to game...")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(10)  # Wait for game to load
        
        print(f"[+] Game loaded: {driver.current_url}")
        
        # Save screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_loaded.png")
        print("[+] Screenshot saved: game_loaded.png")
        
        # Step 3: Find and click Objectives
        print("\n[*] Looking for Objectives...")
        
        # Try to find objectives button/link
        try:
            # Wait for objectives button
            objectives = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//*[contains(text(), 'Objectives') or contains(text(), 'objectives')]"))
            )
            print("[+] Found Objectives button")
            objectives.click()
            time.sleep(3)
        except:
            print("[!] Could not find Objectives button by text")
            # Try by other selectors
            try:
                objectives = driver.find_element(By.CSS_SELECTOR, "[class*='objective'], [id*='objective']")
                print("[+] Found Objectives by selector")
                objectives.click()
                time.sleep(3)
            except:
                print("[!] Could not find Objectives")
        
        # Step 4: Find and click the terminal
        print("\n[*] Looking for terminal...")
        
        # Try to find terminal link/element
        try:
            terminal = WebDriverWait(driver, 10).until(
                EC.element_to_be_clickable((By.XPATH, "//*[contains(text(), 'termOrientation') or contains(text(), 'Terminal')]"))
            )
            print("[+] Found terminal")
            terminal.click()
            time.sleep(10)  # Wait for terminal to load
        except:
            print("[!] Could not find terminal by text")
            # Try finding any terminal elements
            terminals = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal'], [id*='terminal']")
            if terminals:
                print(f"[+] Found {len(terminals)} terminal elements")
                terminals[0].click()
                time.sleep(10)
        
        print(f"[+] Current URL: {driver.current_url}")
        
        # Step 5: Solve the challenge
        if "wetty-prod" in driver.current_url:
            print("\n[*] Terminal is open, solving challenge...")
            
            # Wait for terminal to fully load
            time.sleep(10)
            
            # Find the xterm textarea
            try:
                textarea = WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "textarea.xterm-helper-textarea"))
                )
                print("[+] Found terminal textarea")
                
                # Click and type
                textarea.click()
                time.sleep(1)
                textarea.send_keys("answer")
                time.sleep(1)
                textarea.send_keys(Keys.RETURN)
                print("[+] Submitted 'answer'")
                
                # Wait for response
                time.sleep(5)
                
                # Check for success
                page_source = driver.page_source
                if any(word in page_source.lower() for word in ['congratulations', 'correct', 'completed', 'success']):
                    print("[✓] SUCCESS!")
                else:
                    print("[!] No success confirmation in page source")
                    
            except Exception as e:
                print(f"[!] Error interacting with terminal: {e}")
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_result.png")
        print("\n[+] Final screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Browser closed")

if __name__ == "__main__":
    solve_hhc()
