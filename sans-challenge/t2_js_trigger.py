#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Trigger JavaScript defang functions directly
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
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: Trigger JS Functions")
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
        
        time.sleep(10)
        
        # === EXTRACT IOCS ===
        print("[*] Extracting IOCs...")
        
        # Use JavaScript to trigger form submission
        for ioc_type in ['domain', 'ip', 'url', 'email']:
            print(f"  [*] Extracting {ioc_type}s...")
            
            # Set the regex value
            if ioc_type == 'domain':
                regex = r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+"
            elif ioc_type == 'ip':
                regex = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
            elif ioc_type == 'url':
                regex = r"https?://[^\s\"]+"
            else:  # email
                regex = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
            
            # Click the tab first
            driver.find_element(By.XPATH, f"//button[@data-ioc-type='{ioc_type}s']").click()
            time.sleep(2)
            
            # Clear and set the input
            input_field = driver.find_element(By.ID, f"{ioc_type}-regex")
            input_field.clear()
            input_field.send_keys(regex)
            time.sleep(1)
            
            # Submit the form
            driver.find_element(By.ID, f"{ioc_type}-form").submit()
            print(f"    [+] Form submitted")
            time.sleep(3)
        
        print("\n[+] Extraction complete\n")
        
        # Go to Defang tab
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang tab")
        
        # === DEFANG using JavaScript function calls ===
        print("\n[*] Calling defang functions via JavaScript...")
        
        # Try calling the defang functions if they exist
        defang_js = """
        // Try to call defang functions
        let results = [];
        
        if (typeof defangAllDots === 'function') {
            defangAllDots();
            results.push('defangAllDots called');
        }
        if (typeof defangAtSymbol === 'function') {
            defangAtSymbol();
            results.push('defangAtSymbol called');
        }
        if (typeof defangHttp === 'function') {
            defangHttp();
            results.push('defangHttp called');
        }
        if (typeof defangProtocol === 'function') {
            defangProtocol();
            results.push('defangProtocol called');
        }
        
        return results.join(', ');
        """
        
        result = driver.execute_script(defang_js)
        print(f"  [+] Defang result: {result}")
        time.sleep(3)
        
        # Check defanged list
        defanged = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list: {defanged[:500]}")
        
        # Submit
        print("\n[*] Submitting...")
        driver.find_element(By.ID, "send-iocs").click()
        time.sleep(10)
        
        # Check alert
        try:
            alert = driver.find_element(By.ID, "alert").text
            print(f"[*] Alert: {alert}")
        except:
            print("[!] No alert")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_js_trigger_result.png")
        
        # Verify
        driver.switch_to.default_content()
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in text.lower() or "its all about" in text.lower():
            print("\n[✓✓✓] CHALLENGE COMPLETE!")
            return True
        else:
            print("\n[!] Not in achievements")
            return False

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
