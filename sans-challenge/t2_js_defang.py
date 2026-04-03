#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: JavaScript Defanging
Extract IOCs, then use JavaScript to properly defang
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
    print("SANS HHC 2025 - Terminal 2: JavaScript Defanging")
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
        
        # === STEP 1: EXTRACT IOCS ===
        print("=" * 70)
        print("STEP 1: Extract IOCs")
        print("=" * 70 + "\n")
        
        # Extract all four types
        for ioc_type, pattern in [
            ("domains", r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+"),
            ("ips", r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
            ("urls", r"https?://[^\s\"]+"),
            ("emails", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        ]:
            print(f"[*] Extracting {ioc_type.upper()}...")
            driver.find_element(By.XPATH, f"//button[@data-ioc-type='{ioc_type}' or @data-ioc-type='{ioc_type[:-1]}']").click()
            time.sleep(2)
            
            regex_id = f"{ioc_type[:-1]}-regex" if ioc_type == "urls" else f"{ioc_type[:-1] if ioc_type != 'emails' else 'email'}-regex"
            if ioc_type == "domains":
                regex_id = "domain-regex"
            elif ioc_type == "ips":
                regex_id = "ip-regex"
            elif ioc_type == "urls":
                regex_id = "url-regex"
            elif ioc_type == "emails":
                regex_id = "email-regex"
            
            driver.find_element(By.ID, regex_id).clear()
            driver.find_element(By.ID, regex_id).send_keys(pattern)
            
            form_id = f"{ioc_type[:-1]}-form" if ioc_type == "urls" else f"{ioc_type[:-1] if ioc_type != 'emails' else 'email'}-form"
            if ioc_type == "domains":
                form_id = "domain-form"
            elif ioc_type == "ips":
                form_id = "ip-form"
            elif ioc_type == "urls":
                form_id = "url-form"
            elif ioc_type == "emails":
                form_id = "email-form"
            
            driver.find_element(By.ID, form_id).find_element(By.TAG_NAME, "button").click()
            time.sleep(3)
            print(f"  [+] {ioc_type} extracted")
        
        print("\n[+] All IOCs extracted\n")
        
        # === STEP 2: GO TO DEFANG TAB ===
        print("=" * 70)
        print("STEP 2: Defang using JavaScript")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang & Report tab")
        
        # Check what's in the defanged list
        defanged_before = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list before: {defanged_before[:300]}")
        
        # Try using JavaScript to directly manipulate the defanged items
        print("\n[*] Attempting JavaScript defanging...")
        
        # Execute JavaScript to replace text content
        js_code = """
        // Find all IOC items and defang them
        var items = document.querySelectorAll('.ioc-item span, .defanged-item, #defanged-list .item');
        items.forEach(function(item) {
            var text = item.textContent;
            // Defang: . -> [.], @ -> [@], http -> hxxp, :// -> [://]
            text = text.replace(/\./g, '[.]');
            text = text.replace(/@/g, '[@]');
            text = text.replace(/http/g, 'hxxp');
            text = text.replace(/:\/\//g, '[://]');
            item.textContent = text;
        });
        return "Processed " + items.length + " items";
        """
        
        result = driver.execute_script(js_code)
        print(f"  [+] JavaScript result: {result}")
        time.sleep(2)
        
        # Check defanged list after
        defanged_after = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list after: {defanged_after[:500]}")
        
        # Check for remaining dots and @ symbols
        has_dots = "." in defanged_after.replace("[.]", "").replace("[./]", "")
        has_at = "@" in defanged_after.replace("[@]", "")
        
        if has_dots:
            print("[!] WARNING: Still has un-defanged dots")
        if has_at:
            print("[!] WARNING: Still has un-defanged @")
        
        if not has_dots and not has_at:
            print("\n[✓] All IOCs properly defanged!")
        
        # === STEP 3: SUBMIT ===
        print("\n" + "=" * 70)
        print("STEP 3: Send to Security Team")
        print("=" * 70 + "\n")
        
        driver.execute_script("document.getElementById('send-iocs').click();")
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(10)
        
        # Check alert
        try:
            alert = driver.find_element(By.ID, "alert").text
            print(f"[*] Alert: {alert}")
        except:
            print("[!] No alert")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_js_result.png")
        print("\n[+] Screenshot saved")
        
        # Switch back and verify
        driver.switch_to.default_content()
        
        # Close modal
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        # Verify completion
        print("\n[*] Verifying completion...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in text.lower() or "its all about" in text.lower():
            print("\n[✓✓✓] CHALLENGE CONFIRMED IN ACHIEVEMENTS!")
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
