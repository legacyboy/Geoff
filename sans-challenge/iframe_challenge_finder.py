#!/usr/bin/env python3
"""
SANS HHC 2025 - IFrame Challenge Finder
Look inside the iframe for the challenge UI
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
    print("SANS HHC 2025 - IFrame Challenge Finder")
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
        
        # Open Objectives
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
        
        # Find and switch to iframe
        print("\n[*] Finding iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")
        
        if iframes:
            # Switch to the first iframe
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
            
            # Now look for the challenge UI inside the iframe
            print("\n" + "=" * 60)
            print("INSIDE IFRAME - LOOKING FOR CHALLENGE UI")
            print("=" * 60)
            
            # Wait for iframe to fully load
            time.sleep(10)
            
            # Look for all elements
            print("\n[*] Looking for all elements...")
            
            # Get page source
            page_source = driver.page_source
            print(f"\n[*] Page source length: {len(page_source)}")
            
            # Look for divs
            divs = driver.find_elements(By.TAG_NAME, "div")
            print(f"[*] Found {len(divs)} divs")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"[*] Found {len(inputs)} inputs")
            for i, inp in enumerate(inputs):
                try:
                    attrs = {
                        "type": inp.get_attribute("type"),
                        "id": inp.get_attribute("id"),
                        "class": inp.get_attribute("class"),
                        "placeholder": inp.get_attribute("placeholder"),
                        "visible": inp.is_displayed()
                    }
                    print(f"  [Input {i}] {attrs}")
                except:
                    pass
            
            # Look for textareas
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            print(f"\n[*] Found {len(textareas)} textareas")
            for i, ta in enumerate(textareas):
                try:
                    attrs = {
                        "id": ta.get_attribute("id"),
                        "class": ta.get_attribute("class"),
                        "visible": ta.is_displayed()
                    }
                    print(f"  [Textarea {i}] {attrs}")
                except:
                    pass
            
            # Look for contenteditable
            editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
            print(f"\n[*] Found {len(editables)} contenteditables")
            for i, elem in enumerate(editables):
                try:
                    attrs = {
                        "tag": elem.tag_name,
                        "id": elem.get_attribute("id"),
                        "class": elem.get_attribute("class"),
                        "visible": elem.is_displayed()
                    }
                    print(f"  [Editable {i}] {attrs}")
                except:
                    pass
            
            # Look for spans
            spans = driver.find_elements(By.TAG_NAME, "span")
            print(f"\n[*] Found {len(spans)} spans")
            
            # Get body text
            body_text = driver.find_element(By.TAG_NAME, "body").text
            print(f"\n[*] Body text length: {len(body_text)}")
            print(f"[*] Body text preview:")
            print(body_text[:500])
            
            # Try to execute JavaScript to find elements
            print("\n" + "=" * 60)
            print("JAVASCRIPT ELEMENT SEARCH")
            print("=" * 60)
            
            # Find all elements with 'input' in their id or class
            script = """
                var results = [];
                var allElements = document.querySelectorAll('*');
                for (var i = 0; i < allElements.length; i++) {
                    var el = allElements[i];
                    var id = el.id || '';
                    var className = el.className || '';
                    if (id.toLowerCase().includes('input') || 
                        className.toLowerCase().includes('input') ||
                        id.toLowerCase().includes('answer') ||
                        className.toLowerCase().includes('answer') ||
                        id.toLowerCase().includes('challenge') ||
                        className.toLowerCase().includes('challenge')) {
                        results.push({
                            tag: el.tagName,
                            id: id,
                            class: className,
                            text: el.textContent.substring(0, 100)
                        });
                    }
                }
                return results;
            """
            
            js_results = driver.execute_script(script)
            print(f"\n[*] Found {len(js_results)} elements via JS:")
            for elem in js_results[:20]:
                print(f"  [{elem['tag']}] id={elem['id']}, class={elem['class']}")
                print(f"      text: {elem['text']}")
            
            # Switch back to parent
            driver.switch_to.default_content()
            
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/iframe_challenge.png")
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
