#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Using REFERENCE patterns
Try the exact patterns from the Reference tab
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
    print("SANS HHC 2025 - Terminal 2: Using Reference Patterns")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
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
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
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
        print("[*] Opening Terminal 2...")
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
        
        # === STEP 1: EXTRACT IOCS using REFERENCE patterns ===
        print("=" * 70)
        print("STEP 1: Extract IOCs using Reference patterns")
        print("=" * 70 + "\n")
        
        # DOMAINS - using reference pattern
        print("[*] Extracting DOMAINS...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='domains']").click()
        time.sleep(2)
        driver.find_element(By.ID, "domain-regex").clear()
        # Reference pattern: [a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+
        driver.find_element(By.ID, "domain-regex").send_keys(r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+")
        driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # Check what was extracted
        domain_text = driver.find_element(By.ID, "selected-domains-list").text
        print(f"  Extracted: {domain_text[:200]}")
        
        # IPs - using reference pattern (but fixing the missing octet)
        print("\n[*] Extracting IPs...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='ips']").click()
        time.sleep(2)
        driver.find_element(By.ID, "ip-regex").clear()
        # Reference has: \d{1,3}\.\d{1,3}\.\d{1,3} (missing last octet!)
        # Fixed: \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
        driver.find_element(By.ID, "ip-regex").send_keys(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        driver.find_element(By.ID, "ip-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        ip_text = driver.find_element(By.ID, "selected-ips-list").text
        print(f"  Extracted: {ip_text[:200]}")
        
        # URLs - using reference pattern
        print("\n[*] Extracting URLs...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='urls']").click()
        time.sleep(2)
        driver.find_element(By.ID, "url-regex").clear()
        # Reference: http://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(:[0-9]+)?(/[^\s]*)?
        driver.find_element(By.ID, "url-regex").send_keys(r"https?://[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+(/[^\s]*)?")
        driver.find_element(By.ID, "url-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        url_text = driver.find_element(By.ID, "selected-urls-list").text
        print(f"  Extracted: {url_text[:200]}")
        
        # Emails - using reference pattern
        print("\n[*] Extracting Emails...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='emails']").click()
        time.sleep(2)
        driver.find_element(By.ID, "email-regex").clear()
        # Reference: \b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b
        driver.find_element(By.ID, "email-regex").send_keys(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
        driver.find_element(By.ID, "email-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        email_text = driver.find_element(By.ID, "selected-emails-list").text
        print(f"  Extracted: {email_text[:200]}")
        
        print("\n[+] Extraction complete\n")
        
        # === STEP 2: DEFANG using Quick Buttons with JavaScript ===
        print("=" * 70)
        print("STEP 2: Defang using JavaScript")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang & Report tab")
        
        # Try clicking quick defang buttons via JavaScript
        print("[*] Clicking Quick Defang buttons via JavaScript...")
        
        driver.execute_script("document.getElementById('defang-all-dots').click();")
        print("[+] Clicked: . -> [.]")
        time.sleep(2)
        
        driver.execute_script("document.getElementById('defang-at').click();")
        print("[+] Clicked: @ -> [@]")
        time.sleep(2)
        
        driver.execute_script("document.getElementById('defang-http').click();")
        print("[+] Clicked: HTTP -> HXXP")
        time.sleep(2)
        
        driver.execute_script("document.getElementById('defang-protocol').click();")
        print("[+] Clicked: :// -> [://]")
        time.sleep(3)
        
        # Check defanged list
        defanged_text = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list: {defanged_text[:300]}")
        
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_reference_result.png")
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
