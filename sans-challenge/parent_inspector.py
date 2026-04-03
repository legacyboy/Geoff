#!/usr/bin/env python3
"""
SANS HHC 2025 - Parent Window Inspector
Inspect the parent window DOM above the terminal iframe
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

def inspect():
    print("=" * 60)
    print("SANS HHC 2025 - Parent Window Inspector")
    print("=" * 60 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Login and navigate
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        
        print("[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        
        try:
            ctf = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            ctf.click()
            time.sleep(3)
            print("[+] CTF enabled")
        except:
            pass
        
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        # Click terminal button
        print("[*] Clicking terminal button...")
        try:
            term_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]")
            term_btn.click()
            print("[+] Terminal button clicked")
            time.sleep(15)
        except Exception as e:
            print(f"[!] Button error: {e}")
        
        # Stay in parent window - inspect the area above the iframe
        print("\n[*] Inspecting parent window (above iframe)...")
        
        # Look for any elements that might be the challenge UI
        print("\n=== ALL ELEMENTS ===")
        
        # Find all divs in the parent window
        divs = driver.find_elements(By.TAG_NAME, "div")
        print(f"[*] Total divs in parent: {len(divs)}")
        
        # Look for divs that contain text about challenge or answer
        challenge_divs = []
        for div in divs:
            try:
                text = div.text
                if text and len(text) < 200:  # Reasonable length
                    if any(word in text.lower() for word in ['answer', 'challenge', 'termorientation', 'question', 'input']):
                        challenge_divs.append({
                            'text': text,
                            'id': div.get_attribute('id'),
                            'class': div.get_attribute('class'),
                            'visible': div.is_displayed(),
                            'location': div.location
                        })
            except:
                pass
        
        print(f"\n[*] Found {len(challenge_divs)} challenge-related divs:")
        for div in challenge_divs[:20]:
            print(f"\n  Div: id={div['id']}, class={div['class']}")
            print(f"       visible={div['visible']}, location={div['location']}")
            print(f"       text: {div['text'][:100]}")
        
        # Look for elements with specific roles
        print("\n=== ROLE ELEMENTS ===")
        for role in ['textbox', 'searchbox', 'input', 'form']:
            try:
                elems = driver.find_elements(By.CSS_SELECTOR, f"[role='{role}']")
                print(f"[*] Elements with role='{role}': {len(elems)}")
                for elem in elems:
                    print(f"  - {elem.tag_name}: {elem.get_attribute('class')}")
            except:
                pass
        
        # Look for elements near the top of the page
        print("\n=== TOP PAGE ELEMENTS ===")
        all_elements = driver.find_elements(By.CSS_SELECTOR, "*")
        for elem in all_elements:
            try:
                loc = elem.location
                if loc['y'] < 300:  # Elements in top portion
                    tag = elem.tag_name
                    text = elem.text
                    if text and len(text) < 100:
                        print(f"  [{tag} @ y={loc['y']}] {text[:50]}")
            except:
                pass
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/parent_inspection.png")
        print("\n[+] Screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    inspect()
