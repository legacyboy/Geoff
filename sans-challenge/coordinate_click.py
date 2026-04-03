#!/usr/bin/env python3
"""
SANS HHC 2025 - Coordinate-Based Terminal Click
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
    print("SANS HHC 2025 - Coordinate-Based Terminal Access")
    print("="*60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Login and enter game
        print("[*] Logging in and entering game...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        
        # Click Play Now
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)  # Wait for game
        
        print(f"[+] In game: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/game_for_click.png")
        
        # Click on the terminal icon (left side of screen, based on screenshot)
        # The terminal appears to be on the left side
        print("\n[*] Clicking terminal icon...")
        
        # Try clicking at coordinates where terminal icon appears (left side, middle height)
        actions = ActionChains(driver)
        actions.move_by_offset(200, 400)  # Left side, middle height
        actions.click()
        actions.perform()
        
        time.sleep(10)
        print(f"[*] After click: {driver.current_url}")
        
        # Try another position if first didn't work
        if "wetty" not in driver.current_url:
            print("[*] Trying different coordinate...")
            actions = ActionChains(driver)
            actions.move_by_offset(100, 0)  # Slightly more left
            actions.click()
            actions.perform()
            time.sleep(10)
        
        # Check if terminal opened
        if "wetty" in driver.current_url:
            print("[+] Terminal opened!")
            time.sleep(10)
            
            # Solve
            print("[*] Solving...")
            textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
            textarea.click()
            time.sleep(1)
            textarea.send_keys("answer")
            time.sleep(1)
            textarea.send_keys(Keys.RETURN)
            time.sleep(10)
            print("[+] Submitted")
        else:
            print(f"[!] Terminal not opened. URL: {driver.current_url}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_coord.png")
        print("[+] Screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    solve()
