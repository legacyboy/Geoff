#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: SED with proper form submission
Use submit event on defang form
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
    print("SANS HHC 2025 - Terminal 2: SED with Form Submission")
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
        
        # === EXTRACT IOCS ===
        print("[*] Extracting IOCs...")
        
        # Domains
        driver.find_element(By.XPATH, "//button[@data-ioc-type='domains']").click()
        time.sleep(2)
        driver.find_element(By.ID, "domain-regex").clear()
        driver.find_element(By.ID, "domain-regex").send_keys(r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+")
        driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # IPs
        driver.find_element(By.XPATH, "//button[@data-ioc-type='ips']").click()
        time.sleep(2)
        driver.find_element(By.ID, "ip-regex").clear()
        driver.find_element(By.ID, "ip-regex").send_keys(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
        driver.find_element(By.ID, "ip-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # URLs
        driver.find_element(By.XPATH, "//button[@data-ioc-type='urls']").click()
        time.sleep(2)
        driver.find_element(By.ID, "url-regex").clear()
        driver.find_element(By.ID, "url-regex").send_keys(r"https?://[^\s\"]+")
        driver.find_element(By.ID, "url-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # Emails
        driver.find_element(By.XPATH, "//button[@data-ioc-type='emails']").click()
        time.sleep(2)
        driver.find_element(By.ID, "email-regex").clear()
        driver.find_element(By.ID, "email-regex").send_keys(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "email-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        print("[+] IOCs extracted\n")
        
        # Go to Defang tab
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang tab")
        
        # === USE SED WITH FORM SUBMISSION ===
        print("[*] Applying SED commands...")
        
        sed_input = driver.find_element(By.ID, "defang-sed")
        
        # Command 1: Replace dots
        sed_input.clear()
        sed_input.send_keys(r"s/\./[.]/g")
        print("  [+] Entered: s/\\./[.]/g")
        
        # Submit the form by clicking the submit button
        submit_btn = driver.find_element(By.XPATH, "//form[@id='defang-form']//button[@type='submit']")
        submit_btn.click()
        print("  [+] Clicked Apply")
        time.sleep(3)
        
        # Command 2: Replace @
        sed_input.clear()
        sed_input.send_keys(r"s/@/[@]/g")
        print("  [+] Entered: s/@/[@]/g")
        submit_btn.click()
        print("  [+] Clicked Apply")
        time.sleep(3)
        
        # Command 3: Replace http
        sed_input.clear()
        sed_input.send_keys(r"s/http/hxxp/g")
        print("  [+] Entered: s/http/hxxp/g")
        submit_btn.click()
        print("  [+] Clicked Apply")
        time.sleep(3)
        
        # Check defanged list
        defanged = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list:\n{defanged}\n")
        
        # Check if properly defanged
        has_unescaped_dot = "." in defanged.replace("[.]", "").replace("[./]", "")
        has_unescaped_at = "@" in defanged.replace("[@]", "")
        
        if has_unescaped_dot:
            print("[!] WARNING: Still has unescaped dots")
        if has_unescaped_at:
            print("[!] WARNING: Still has unescaped @")
        
        # Submit
        print("[*] Submitting...")
        driver.find_element(By.ID, "send-iocs").click()
        time.sleep(10)
        
        # Check alert
        try:
            alert = driver.find_element(By.ID, "alert").text
            print(f"[*] Alert: {alert}")
        except:
            print("[!] No alert")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_sed_submit_result.png")
        
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
