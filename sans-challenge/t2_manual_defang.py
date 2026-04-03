#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Manual Defang Entry
Try entering defanged IOCs manually
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
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: Manual Defang Entry")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Open Terminal 2
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]").click()
                    print(f"[+] Opened: {title}")
                    break
            except:
                pass
        
        time.sleep(45)
        print("[+] Terminal loaded\n")
        
        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        
        time.sleep(5)
        
        # === SKIP TO DEFANG TAB ===
        print("=" * 70)
        print("Going directly to Defang & Report tab")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang & Report tab\n")
        
        # === LOOK FOR MANUAL INPUT ===
        print("[*] Looking for input fields...")
        
        # Find all inputs on the defang tab
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"  Found {len(inputs)} input fields")
        for i, inp in enumerate(inputs):
            try:
                inp_id = inp.get_attribute("id") or ""
                inp_type = inp.get_attribute("type") or ""
                placeholder = inp.get_attribute("placeholder") or ""
                print(f"    {i+1}. id={inp_id}, type={inp_type}, placeholder={placeholder[:50]}")
            except:
                pass
        
        # Find all textareas
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"\n  Found {len(textareas)} textarea fields")
        for i, ta in enumerate(textareas):
            try:
                ta_id = ta.get_attribute("id") or ""
                print(f"    {i+1}. id={ta_id}")
            except:
                pass
        
        # Look for editable divs
        editable_divs = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"\n  Found {len(editable_divs)} editable divs")
        
        # Check defanged list structure
        print("\n[*] Checking defanged list structure...")
        defanged_html = driver.find_element(By.ID, "defanged-list").get_attribute("innerHTML")
        print(f"  Defanged list HTML: {defanged_html[:500]}")
        
        # Check if there's a hidden form or input
        print("\n[*] Looking for form elements...")
        forms = driver.find_elements(By.TAG_NAME, "form")
        print(f"  Found {len(forms)} forms")
        for form in forms:
            form_id = form.get_attribute("id") or ""
            print(f"    Form id: {form_id}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_defang_structure.png")
        print("\n[+] Screenshot saved: t2_defang_structure.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
