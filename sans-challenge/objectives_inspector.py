#!/usr/bin/env python3
"""
SANS HHC 2025 - Objectives Page Inspector
Check Objectives page BEFORE clicking terminal button
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
    print("SANS HHC 2025 - Objectives Page Inspector")
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
        
        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        
        # Enable CTF
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
        
        # Open Objectives - DON'T click terminal yet
        print("\n[*] Opening Objectives (pre-terminal click)...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        print("[+] Objectives loaded\n")
        print("=" * 60)
        print("ANALYZING OBJECTIVES PAGE")
        print("=" * 60)
        
        # Look for any input fields
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"\n[*] Found {len(inputs)} input elements:")
        for i, inp in enumerate(inputs):
            try:
                attrs = {
                    "type": inp.get_attribute("type"),
                    "id": inp.get_attribute("id"),
                    "class": inp.get_attribute("class"),
                    "placeholder": inp.get_attribute("placeholder"),
                    "visible": inp.is_displayed()
                }
                if attrs["visible"]:
                    print(f"  [Input {i}] {attrs}")
            except:
                pass
        
        # Look for textareas
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"\n[*] Found {len(textareas)} textarea elements:")
        for i, ta in enumerate(textareas):
            try:
                attrs = {
                    "id": ta.get_attribute("id"),
                    "class": ta.get_attribute("class"),
                    "visible": ta.is_displayed()
                }
                if attrs["visible"]:
                    print(f"  [Textarea {i}] {attrs}")
            except:
                pass
        
        # Look for contenteditable
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"\n[*] Found {len(editables)} contenteditable elements:")
        for i, elem in enumerate(editables):
            try:
                if elem.is_displayed():
                    print(f"  [Editable {i}] tag={elem.tag_name}, id={elem.get_attribute('id')}, class={elem.get_attribute('class')}")
            except:
                pass
        
        # Look for challenge-related elements
        print("\n[*] Searching for challenge-related text...")
        challenge_keywords = ['termOrientation', 'answer', 'Answer', 'challenge', 'Challenge', 'input', 'terminal', 'question']
        
        for keyword in challenge_keywords:
            try:
                elems = driver.find_elements(By.XPATH, f"//*[contains(text(), '{keyword}')]")
                visible_elems = [e for e in elems if e.is_displayed()]
                if visible_elems:
                    print(f"\n  Elements with '{keyword}' ({len(visible_elems)} visible):")
                    for elem in visible_elems[:5]:
                        try:
                            text = elem.text[:100]
                            tag = elem.tag_name
                            elem_id = elem.get_attribute('id')
                            elem_class = elem.get_attribute('class')
                            print(f"    [{tag}] id={elem_id}, class={elem_class}")
                            print(f"    text: {text}")
                        except:
                            pass
            except:
                pass
        
        # Get full page text
        print("\n" + "=" * 60)
        print("FULL PAGE TEXT")
        print("=" * 60)
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(body_text[:1000])
        
        # Save screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_detailed.png")
        print("\n[+] Screenshot saved")
        
        # Now click the terminal button and check what changes
        print("\n" + "=" * 60)
        print("CLICKING TERMINAL BUTTON")
        print("=" * 60)
        
        try:
            term_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]")
            term_btn.click()
            print("[+] Terminal button clicked")
            time.sleep(15)
        except Exception as e:
            print(f"[!] Button error: {e}")
        
        # Re-check for inputs after terminal opens
        print("\n[*] Re-checking for inputs after terminal opened...")
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Now {len(inputs)} input elements")
        
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"[*] Now {len(textareas)} textarea elements")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_terminal.png")
        print("\n[+] Final screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    inspect()
