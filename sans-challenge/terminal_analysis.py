#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal Element Analysis
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
    print("SANS HHC 2025 - Terminal Analysis")
    print("="*60 + "\n")
    
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
        
        print("[*] Opening Settings...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        
        print("[*] Enabling CTF Style...")
        try:
            ctf = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            driver.execute_script("arguments[0].click();", ctf)
            time.sleep(3)
        except:
            pass
        
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/analysis_objectives.png")
        print("[+] Objectives page loaded")
        
        # Analyze terminal element
        print("\n[*] Analyzing terminal element...")
        
        # Get all elements with terminal-related classes
        elements = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal'], [class*='ent'], [id*='terminal']")
        print(f"[+] Found {len(elements)} potential terminal elements")
        
        for i, elem in enumerate(elements[:5]):
            try:
                html = elem.get_attribute('outerHTML')
                print(f"\n--- Element {i+1} ---")
                print(f"Tag: {elem.tag_name}")
                print(f"Class: {elem.get_attribute('class')}")
                print(f"ID: {elem.get_attribute('id')}")
                print(f"Text: {elem.text[:100] if elem.text else 'None'}")
                
                # Check if it's clickable
                clickable = elem.is_displayed() and elem.is_enabled()
                print(f"Clickable: {clickable}")
                
                # Check for href or onclick
                href = elem.get_attribute('href')
                onclick = elem.get_attribute('onclick')
                print(f"Href: {href}")
                print(f"Onclick: {onclick}")
                
            except Exception as e:
                print(f"[!] Error analyzing element {i}: {e}")
        
        # Also try to find by examining the page structure
        print("\n[*] Examining page structure...")
        
        # Look for clickable divs or links
        all_links = driver.find_elements(By.TAG_NAME, "a")
        print(f"[+] Found {len(all_links)} links")
        
        for link in all_links[:10]:
            try:
                href = link.get_attribute('href')
                if href and 'terminal' in href.lower():
                    print(f"\n[*] Terminal link found: {href}")
                    print(f"[*] Clicking link...")
                    link.click()
                    time.sleep(15)
                    break
            except:
                pass
        
        print(f"\n[*] Current URL: {driver.current_url}")
        
        # If still in objectives, try to open terminal directly by URL
        if "objective" in driver.current_url:
            print("\n[*] Trying direct terminal URL...")
            driver.get("https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA")
            time.sleep(15)
            print(f"[*] After direct nav: {driver.current_url}")
        
        # Solve if terminal opened
        if "wetty" in driver.current_url:
            print("\n[*] Terminal open! Solving...")
            time.sleep(10)
            
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, "textarea.xterm-helper-textarea")
                textarea.click()
                time.sleep(2)
                textarea.send_keys("answer")
                time.sleep(2)
                textarea.send_keys(Keys.RETURN)
                time.sleep(10)
                print("[+] Submitted")
            except Exception as e:
                print(f"[!] Error: {e}")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/analysis_result.png")
        print("\n[+] Screenshot saved")
        
    except Exception as e:
        print(f"[!] Error: {e}")
    
    finally:
        input("\nPress Enter to close...")
        driver.quit()

if __name__ == "__main__":
    solve()
