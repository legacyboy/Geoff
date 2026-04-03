#!/usr/bin/env python3
"""
SANS HHC 2025 - Complete Game Flow
Login -> Character Setup -> Game World -> Objectives -> Terminal -> Solve
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

def click_element(driver, selector, by=By.CSS_SELECTOR, timeout=10):
    """Safely click an element"""
    try:
        elem = WebDriverWait(driver, timeout).until(EC.element_to_be_clickable((by, selector)))
        elem.click()
        return True
    except:
        try:
            elem = driver.find_element(by, selector)
            driver.execute_script("arguments[0].click();", elem)
            return True
        except:
            return False

def solve():
    print("="*60)
    print("SANS HHC 2025 - Complete Game Flow")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 15)
    
    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print(f"[+] Logged in")
        
        # Step 2: Click "Play Now!"
        print("\n[*] Step 2: Clicking 'Play Now!'...")
        click_element(driver, "//button[contains(text(), 'Play Now')]", By.XPATH)
        time.sleep(10)
        print(f"[+] Game loading... {driver.current_url}")
        
        # Step 3: Handle Character Setup (if present)
        print("\n[*] Step 3: Checking for character setup...")
        time.sleep(5)
        
        # Look for "Next" button (character setup)
        if click_element(driver, "//button[contains(text(), 'Next')]", By.XPATH, 5):
            print("[+] Clicked 'Next' on character setup")
            time.sleep(5)
            
            # May have multiple Next buttons
            for i in range(5):
                if click_element(driver, "//button[contains(text(), 'Next')]", By.XPATH, 3):
                    print(f"  Clicked Next {i+1}")
                    time.sleep(3)
                else:
                    break
        
        # Step 4: Look for "Let's go!" or enter game world
        print("\n[*] Step 4: Entering game world...")
        click_element(driver, "//button[contains(text(), 'go')]", By.XPATH, 5)
        click_element(driver, "//button[contains(text(), 'Start')]", By.XPATH, 5)
        time.sleep(10)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/in_game_world.png")
        print(f"[+] In game world: {driver.current_url}")
        
        # Step 5: Click Objectives
        print("\n[*] Step 5: Opening Objectives...")
        time.sleep(5)
        
        # Try to find objectives
        try:
            obj = driver.find_element(By.XPATH, "//*[contains(text(), 'Objectives')]")
            driver.execute_script("arguments[0].click();", obj)
            print("[+] Clicked Objectives")
            time.sleep(5)
        except:
            print("[!] Could not find Objectives")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_open.png")
        
        # Step 6: Find and click termOrientation terminal
        print("\n[*] Step 6: Looking for termOrientation terminal...")
        
        # Look for terminal by various methods
        terminal_found = False
        
        # Method 1: By text
        try:
            term = driver.find_element(By.XPATH, "//*[contains(text(), 'termOrientation')]")
            print("[+] Found termOrientation by text")
            driver.execute_script("arguments[0].click();", term)
            terminal_found = True
        except:
            pass
        
        # Method 2: By class
        if not terminal_found:
            try:
                term = driver.find_element(By.CSS_SELECTOR, "[class*='termOrientation']")
                print("[+] Found termOrientation by class")
                driver.execute_script("arguments[0].click();", term)
                terminal_found = True
            except:
                pass
        
        # Method 3: Any terminal
        if not terminal_found:
            terms = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal']")
            if terms:
                print(f"[+] Found {len(terms)} terminals, clicking first")
                driver.execute_script("arguments[0].click();", terms[0])
                terminal_found = True
        
        if terminal_found:
            print("[*] Clicked terminal, waiting for load...")
            time.sleep(15)  # Wait for terminal to fully load
            
            # Step 7: Solve the challenge
            if "wetty" in driver.current_url:
                print("\n[*] Step 7: Solving challenge...")
                time.sleep(10)
                
                try:
                    # Find and interact with terminal
                    textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                    textarea.click()
                    time.sleep(2)
                    
                    # Type answer
                    print("[*] Typing 'answer'...")
                    textarea.send_keys("answer")
                    time.sleep(2)
                    
                    # Submit
                    print("[*] Submitting...")
                    textarea.send_keys(Keys.RETURN)
                    time.sleep(10)  # Wait for response
                    
                    # Check for success
                    page_text = driver.find_element(By.TAG_NAME, "body").text
                    if any(word in page_text.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award']):
                        print("\n[✓] CHALLENGE SOLVED!")
                    else:
                        print("\n[!] Challenge submitted, checking screenshot...")
                        
                except Exception as e:
                    print(f"[!] Error solving: {e}")
            else:
                print(f"[!] Terminal not in URL: {driver.current_url}")
        else:
            print("[!] Could not find terminal")
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_challenge.png")
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
