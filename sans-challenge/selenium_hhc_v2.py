#!/usr/bin/env python3
"""
SANS HHC 2025 - Full GUI Browser Automation V2
Fixed element interaction and scrolling
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def safe_click(driver, element):
    """Safely click an element with multiple fallback strategies"""
    try:
        # Try regular click
        element.click()
        return True
    except:
        try:
            # Try scrolling into view first
            driver.execute_script("arguments[0].scrollIntoView(true);", element)
            time.sleep(1)
            element.click()
            return True
        except:
            try:
                # Try JavaScript click
                driver.execute_script("arguments[0].click();", element)
                return True
            except:
                return False

def solve_hhc():
    print("="*60)
    print("SANS HHC 2025 - GUI Automation V2")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    
    os.environ['DISPLAY'] = ':0'
    
    print("[*] Launching Firefox...")
    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 15)
    
    try:
        # Step 1: Login
        print("[*] Navigating to login...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        print("[*] Logging in...")
        # Find and fill email
        email_field = driver.find_element(By.CSS_SELECTOR, "input[type='email'], input[name='email'], #email")
        email_field.clear()
        email_field.send_keys(EMAIL)
        
        # Find and fill password
        password_field = driver.find_element(By.CSS_SELECTOR, "input[type='password'], input[name='password'], #password")
        password_field.clear()
        password_field.send_keys(PASSWORD)
        
        # Submit
        password_field.send_keys(Keys.RETURN)
        time.sleep(5)
        
        print(f"[+] Logged in: {driver.current_url}")
        
        # Step 2: Go to game
        print("\n[*] Loading game...")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(15)  # Wait for React to fully load
        
        print(f"[+] Game loaded: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_initial.png")
        
        # Step 3: Find and click Objectives
        print("\n[*] Looking for Objectives...")
        
        try:
            # Wait for the game to render
            time.sleep(5)
            
            # Try to find Objectives by different methods
            objectives_selectors = [
                "//*[text()='Objectives']",
                "//*[contains(text(), 'Objectives')]",
                "[class*='objective']",
                "[id*='objective']",
                "button:contains('Objectives')"
            ]
            
            for selector in objectives_selectors:
                try:
                    if selector.startswith("//"):
                        obj = driver.find_element(By.XPATH, selector)
                    else:
                        obj = driver.find_element(By.CSS_SELECTOR, selector)
                    
                    if obj:
                        print(f"[+] Found Objectives: {selector}")
                        safe_click(driver, obj)
                        time.sleep(3)
                        break
                except:
                    continue
        except Exception as e:
            print(f"[!] Objectives click error: {e}")
        
        # Step 4: Find terminal
        print("\n[*] Looking for termOrientation terminal...")
        
        # Wait a bit for any transitions
        time.sleep(3)
        
        # Try to find terminal
        terminal_selectors = [
            "[class*='terminal-termOrientation']",
            "[class*='termOrientation']",
            "//*[contains(text(), 'termOrientation')]",
            "[class*='ent type-terminal']"
        ]
        
        terminal = None
        for selector in terminal_selectors:
            try:
                if selector.startswith("//"):
                    terminal = driver.find_element(By.XPATH, selector)
                else:
                    terminal = driver.find_element(By.CSS_SELECTOR, selector)
                
                if terminal:
                    print(f"[+] Found terminal: {selector}")
                    break
            except:
                continue
        
        if terminal:
            print("[*] Clicking terminal...")
            if safe_click(driver, terminal):
                print("[+] Terminal clicked")
                time.sleep(10)  # Wait for terminal to load
            else:
                print("[!] Could not click terminal")
        
        # Step 5: Solve challenge if terminal opened
        if "wetty-prod" in driver.current_url:
            print("\n[*] Terminal is open! Solving...")
            
            time.sleep(10)  # Wait for terminal
            
            try:
                # Find the xterm textarea
                textarea = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, "textarea.xterm-helper-textarea")))
                print("[+] Found terminal textarea")
                
                # Click and enter answer
                textarea.click()
                time.sleep(1)
                textarea.send_keys("answer")
                time.sleep(1)
                textarea.send_keys(Keys.RETURN)
                print("[+] Submitted 'answer'")
                
                time.sleep(5)
                
                # Check for success
                page_text = driver.find_element(By.TAG_NAME, "body").text
                if any(word in page_text.lower() for word in ['congratulations', 'correct', 'completed', 'success']):
                    print("[✓] SUCCESS!")
                else:
                    print("[!] No immediate success confirmation")
                    
            except Exception as e:
                print(f"[!] Terminal interaction error: {e}")
        else:
            print(f"\n[!] Terminal not opened. Current URL: {driver.current_url}")
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_v2.png")
        print("\n[+] Final screenshot saved")
        
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Browser closed")

if __name__ == "__main__":
    solve_hhc()
