#!/usr/bin/env python3
"""
SANS HHC 2025 - IFrame Inspector
Check what's inside the iframe
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
    print("SANS HHC 2025 - IFrame Inspector")
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
        
        # Find and inspect iframe
        print("\n[*] Inspecting iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            try:
                src = iframe.get_attribute("src")
                print(f"\n[Iframe {i}] src={src}")
                
                # Switch to iframe
                driver.switch_to.frame(iframe)
                print(f"[*] Switched to iframe {i}")
                
                # Inspect contents
                print("[*] Searching for input elements in iframe...")
                inputs = driver.find_elements(By.TAG_NAME, "input")
                print(f"[+] Found {len(inputs)} input elements")
                
                for j, inp in enumerate(inputs):
                    try:
                        attrs = {
                            "type": inp.get_attribute("type"),
                            "id": inp.get_attribute("id"),
                            "class": inp.get_attribute("class"),
                            "placeholder": inp.get_attribute("placeholder"),
                            "name": inp.get_attribute("name"),
                            "visible": inp.is_displayed()
                        }
                        print(f"  [Input {j}] {attrs}")
                    except:
                        pass
                
                # Check for textareas
                textareas = driver.find_elements(By.TAG_NAME, "textarea")
                print(f"\n[+] Found {len(textareas)} textarea elements")
                
                for j, ta in enumerate(textareas):
                    try:
                        attrs = {
                            "id": ta.get_attribute("id"),
                            "class": ta.get_attribute("class"),
                            "visible": ta.is_displayed()
                        }
                        print(f"  [Textarea {j}] {attrs}")
                    except:
                        pass
                
                # Check body text
                body_text = driver.find_element(By.TAG_NAME, "body").text
                print(f"\n[+] Body text preview:")
                print(body_text[:500])
                
                # Switch back to main content
                driver.switch_to.default_content()
                
            except Exception as e:
                print(f"[!] Iframe {i} error: {e}")
                driver.switch_to.default_content()
        
        # Also check dialogs
        print("\n[*] Checking dialogs...")
        dialogs = driver.find_elements(By.CSS_SELECTOR, "[role='dialog'], .modal")
        print(f"[*] Found {len(dialogs)} dialogs")
        
        for i, dialog in enumerate(dialogs):
            try:
                if dialog.is_displayed():
                    print(f"\n[Dialog {i}] visible=True")
                    html = dialog.get_attribute("outerHTML")[:500]
                    print(f"HTML: {html}...")
            except:
                pass
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/iframe_inspection.png")
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
