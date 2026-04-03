#!/usr/bin/env python3
"""
SANS HHC 2025 - Find and Click Gear Precisely
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
    print("SANS HHC 2025 - Precise Gear Click")
    print("="*60 + "\n")
    
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
        
        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print(f"[+] Game loaded")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/before_gear.png")
        
        # Try to find gear icon by looking for button elements in top right
        print("\n[*] Looking for gear/settings button...")
        time.sleep(5)
        
        # Get all buttons
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"[+] Found {len(buttons)} buttons")
        
        # Check each button's position
        for i, btn in enumerate(buttons):
            try:
                loc = btn.location
                size = btn.size
                # If button is in top right quadrant
                if loc['x'] > 1000 and loc['y'] < 100:
                    print(f"  Button {i}: pos({loc['x']}, {loc['y']}) size({size['width']}, {size['height']})")
                    
                    # Try clicking this button
                    print(f"[*] Clicking button {i}...")
                    driver.execute_script("arguments[0].click();", btn)
                    time.sleep(3)
                    
                    driver.save_screenshot(f"/home/claw/.openclaw/workspace/sans-challenge/after_button_{i}.png")
                    print(f"[+] Screenshot saved: after_button_{i}.png")
                    
                    # Check if settings menu appeared
                    html = driver.page_source
                    if 'settings' in html.lower() or 'ctf' in html.lower():
                        print("[+] Settings menu detected!")
                        break
            except:
                continue
        
        # Also try clicking at specific top-right coordinates
        print("\n[*] Trying precise coordinate click...")
        
        # Common positions for settings gear
        positions = [
            (1350, 80),  # Far top right
            (1300, 50),  # Top right
            (1250, 100), # Slightly left
            (1320, 70),  # Adjusted
        ]
        
        for x, y in positions:
            print(f"[*] Clicking at ({x}, {y})...")
            actions = ActionChains(driver)
            actions.move_by_offset(x, y)
            actions.click()
            actions.perform()
            time.sleep(2)
            
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/sans-challenge/click_at_{x}_{y}.png")
        
        print("\n[+] Screenshots saved. Check them to see what was clicked.")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    solve()
