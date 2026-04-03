#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Direct Iframe Access
Access the iframe directly and interact with it
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
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 Direct Iframe")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Step 1: Login first
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Navigate directly to the terminal iframe URL
        print("\n[*] Navigating directly to terminal iframe...")
        terminal_url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation"
        driver.get(terminal_url)
        time.sleep(15)  # Wait for terminal to load
        
        print(f"[*] Current URL: {driver.current_url}")
        
        # Save initial screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_iframe_initial.png")
        print("[+] Initial screenshot saved")
        
        # Get page content
        html = driver.page_source
        print(f"\n[*] Page HTML length: {len(html)} chars")
        
        # Find all inputs
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} inputs")
        
        for i, inp in enumerate(inputs):
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        type: el.type,
                        id: el.id,
                        class: el.className,
                        placeholder: el.placeholder,
                        visible: el.offsetParent !== null
                    };
                """, inp)
                print(f"  [{i}] type={attrs['type']}, class={attrs['class']}, visible={attrs['visible']}, placeholder='{attrs['placeholder']}'")
            except:
                pass
        
        # Look for textareas (xterm helper)
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"\n[*] Found {len(textareas)} textareas")
        
        for i, ta in enumerate(textareas):
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        id: el.id,
                        class: el.className,
                        visible: el.offsetParent !== null
                    };
                """, ta)
                print(f"  [{i}] class={attrs['class']}, visible={attrs['visible']}")
                
                if attrs['visible']:
                    print(f"\n[>] Found visible textarea! Interacting with it...")
                    
                    # Click on it
                    ta.click()
                    time.sleep(2)
                    
                    # Type answer
                    print("[*] Typing 'answer'...")
                    ta.send_keys("answer")
                    time.sleep(1)
                    
                    # Submit
                    print("[*] Submitting...")
                    ta.send_keys(Keys.RETURN)
                    time.sleep(5)
                    
                    print("[+] Submitted!")
                    
            except Exception as e:
                print(f"  [!] Error with textarea {i}: {e}")
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_iframe_result.png")
        print("\n[+] Final screenshot saved")
        
        # Check page text
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"\n[*] Page text: {body_text[:500]}")
        
        success = ['congratulations', 'correct', 'completed', 'success', 'badge', '2']
        found = [s for s in success if s in body_text.lower()]
        if found:
            print(f"\n[✓] SUCCESS! Indicators: {found}")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        time.sleep(5)
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
