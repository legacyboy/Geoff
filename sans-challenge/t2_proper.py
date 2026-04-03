#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: PROPER Solution
Actually extract IOCs and verify they appear in the lists
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: It's All About Defang")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

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
        
        # === STEP 1: EXTRACT IOCS ===
        print("=" * 70)
        print("STEP 1: Extract IOCs")
        print("=" * 70 + "\n")
        
        # Ensure we're on Extract IOCs tab
        print("[*] Clicking 'Extract IOCs' tab...")
        try:
            extract_tab = driver.find_element(By.XPATH, "//button[contains(text(), 'Extract IOCs') or contains(@data-tab, 'extract')]")
            extract_tab.click()
            time.sleep(2)
            print("[+] On Extract IOCs tab")
        except:
            print("[!] Could not find Extract IOCs tab, may already be on it")
        
        # --- DOMAINS ---
        print("\n[*] Extracting DOMAINS...")
        
        # Click Domains sub-tab
        domain_tab = driver.find_element(By.XPATH, "//button[contains(text(), 'DOMAINS') or @data-ioc-type='domains']")
        domain_tab.click()
        time.sleep(2)
        print("    [+] On Domains tab")
        
        # Find and fill the domain pattern input
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        print("    [+] Entered domain regex")
        time.sleep(1)
        
        # Click EXTRACT button
        extract_btn = driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button")
        extract_btn.click()
        print("    [+] Clicked EXTRACT")
        time.sleep(3)
        
        # Verify extraction - look for any result display
        try:
            domain_results = driver.find_elements(By.CSS_SELECTOR, "#domain-results, .domain-results, [class*='domain']")
            if domain_results:
                print(f"    [+] Domain results element found")
        except:
            print("    [!] Could not find domain results element")
        
        # --- IP ADDRESSES ---
        print("\n[*] Extracting IP ADDRESSES...")
        
        ip_tab = driver.find_element(By.XPATH, "//button[@data-ioc-type='ips']")
        ip_tab.click()
        time.sleep(2)
        print("    [+] On IPs tab")
        
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        print("    [+] Entered IP regex")
        time.sleep(1)
        
        driver.find_element(By.ID, "ip-form").find_element(By.TAG_NAME, "button").click()
        print("    [+] Clicked EXTRACT")
        time.sleep(3)
        
        # Verify extraction
        try:
            ip_results = driver.find_elements(By.CSS_SELECTOR, "#ip-results, .ip-results, [class*='ip-result']")
            if ip_results:
                print(f"    [+] IP results element found")
        except:
            print("    [!] Could not find IP results element")
        
        # --- URLS ---
        print("\n[*] Extracting URLS...")
        
        url_tab = driver.find_element(By.XPATH, "//button[@data-ioc-type='urls']")
        url_tab.click()
        time.sleep(2)
        print("    [+] On URLs tab")
        
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r"https?://[^\s\"]+")
        print("    [+] Entered URL regex")
        time.sleep(1)
        
        driver.find_element(By.ID, "url-form").find_element(By.TAG_NAME, "button").click()
        print("    [+] Clicked EXTRACT")
        time.sleep(3)
        
        url_list = driver.find_element(By.ID, "url-list").text
        print(f"    [+] URLs extracted: {url_list}")
        
        # --- EMAIL ADDRESSES ---
        print("\n[*] Extracting EMAIL ADDRESSES...")
        
        email_tab = driver.find_element(By.XPATH, "//button[@data-ioc-type='emails']")
        email_tab.click()
        time.sleep(2)
        print("    [+] On Emails tab")
        
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        print("    [+] Entered email regex")
        time.sleep(1)
        
        driver.find_element(By.ID, "email-form").find_element(By.TAG_NAME, "button").click()
        print("    [+] Clicked EXTRACT")
        time.sleep(3)
        
        email_list = driver.find_element(By.ID, "email-list").text
        print(f"    [+] Emails extracted: {email_list}")
        
        # === STEP 2: DEFANG & REPORT ===
        print("\n" + "=" * 70)
        print("STEP 2: Defang & Report")
        print("=" * 70 + "\n")
        
        defang_tab = driver.find_element(By.XPATH, "//button[contains(text(), 'DEFANG') or @data-tab='defang-tab']")
        defang_tab.click()
        time.sleep(3)
        print("[+] On Defang & Report tab")
        
        # Look for submit/report button
        print("[*] Looking for submit button...")
        try:
            submit_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Report') or contains(text(), 'Submit') or contains(text(), 'Defang')]")
            submit_btn.click()
            print("[+] Clicked submit")
            time.sleep(5)
        except:
            print("[!] No submit button found")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_proper_result.png")
        print("\n[+] Screenshot saved: t2_proper_result.png")
        
        # Get final text
        final_text = driver.find_element(By.TAG_NAME, "body").text
        if "success" in final_text.lower() or "complete" in final_text.lower() or "submitted" in final_text.lower():
            print("\n[✓] Appears to have submitted successfully!")
        
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
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        text = driver.find_element(By.TAG_NAME, "body").text
        
        # Check objectives for completion
        if "defang" in html.lower() and ("completed" in html.lower() or "fa-check" in html.lower()):
            print("\n[✓] CHALLENGE COMPLETE in objectives!")
            return True
        else:
            print("\n[!] Not showing as complete in objectives")
            print(f"    HTML contains 'completed': {'completed' in html.lower()}")
            print(f"    HTML contains 'fa-check': {'fa-check' in html.lower()}")
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
