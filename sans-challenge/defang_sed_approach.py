#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - SED Approach
Uses the SED command input field to defang IOCs
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os
import re

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - Defang Challenge - SED APPROACH")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Step 2: Enter game
        print("[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game\n")

        # Step 3: Enable CTF mode
        print("[*] Step 3: Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
            print("[+] CTF mode enabled\n")
        except:
            print("[!] CTF mode may already be enabled\n")

        # Step 4: Open defang terminal
        print("[*] Step 4: Opening defang terminal...")
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
        
        # Step 5: Switch to iframe
        print("[*] Step 5: Switching to iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        else:
            print("[!] No iframe found\n")
        
        time.sleep(10)
        
        # Step 6: EXTRACT IOCS using the regex forms
        print("=" * 70)
        print("STEP 6: Extracting IOCs using regex forms")
        print("=" * 70 + "\n")
        
        # Extract Domains
        print("[*] Extracting domains...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}')
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(2)
        
        # Extract IPs
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(1)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(2)
        
        # Extract URLs
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(1)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https?://[^\s]+')
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(2)
        
        # Extract Emails
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(1)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(2)
        
        print("[+] All IOCs extracted\n")
        
        # Step 7: Switch to Defang tab
        print("=" * 70)
        print("STEP 7: Switching to Defang tab")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(5)
        print("[+] On Defang tab\n")
        
        # Step 8: Use SED command to defang
        print("=" * 70)
        print("STEP 8: Applying SED defang command")
        print("=" * 70 + "\n")
        
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        
        # SED command to defang: replace dots with [.] and @ with [@] and http with hxxp
        sed_command = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[://]/g'
        sed_input.send_keys(sed_command)
        print(f"[*] Entered SED command: {sed_command}")
        
        # Click Apply
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        print("[+] Applied SED command")
        time.sleep(5)
        
        # Step 9: Verify defanged list
        print("=" * 70)
        print("STEP 9: Verifying defanged list")
        print("=" * 70 + "\n")
        
        check_js = """
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            const items = defangedList.querySelectorAll('.defanged-item');
            const text = defangedList.textContent;
            return {
                itemCount: items.length,
                preview: text.substring(0, 500),
                fullText: text
            };
        }
        return { itemCount: 0, preview: 'not found' };
        """
        
        check_result = driver.execute_script(check_js)
        print(f"[*] Defanged list: {check_result['itemCount']} items")
        print(f"[*] Preview: {check_result['preview'][:300]}\n")
        
        # Step 10: Submit
        print("=" * 70)
        print("STEP 10: Submitting to Security Team")
        print("=" * 70 + "\n")
        
        send_btn = driver.find_element(By.ID, "send-iocs")
        print(f"[*] Send button enabled: {send_btn.is_enabled()}")
        
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(15)
        
        # Check for alert
        alert_js = """
        const alertBox = document.getElementById('alert');
        return alertBox ? alertBox.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")
        
        # Step 11: Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_sed_result.png")
        print("[+] Screenshot saved\n")
        
        # Step 12: Verify completion
        print("=" * 70)
        print("STEP 12: Verifying completion")
        print("=" * 70 + "\n")
        
        driver.switch_to.default_content()
        
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(15)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in text.lower() or "all about" in text.lower():
            print("\n" + "=" * 70)
            print("[✓✓✓] CHALLENGE COMPLETE!")
            print("=" * 70)
            return True
        else:
            print("\n[!] Challenge NOT in achievements")
            return False

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
