#!/usr/bin/env python3
"""
SANS HHC 2025 - Manual extraction of ALL IOCs
Extract EVERYTHING from the email, then defang
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
    print("SANS HHC 2025 - Defang Challenge - Manual ALL IOCs")
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
        print("[+] Logged in")

        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game")

        print("[*] Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(8)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(5)
            print("[+] CTF mode enabled")
        except:
            pass

        print("[*] Opening terminal...")
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
        
        time.sleep(50)
        print("[+] Terminal loaded")

        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")

        time.sleep(10)

        # STEP 1: Extract ALL IOCs (not just malicious ones)
        print("\n" + "=" * 70)
        print("STEP 1: Extracting ALL IOCs from the email")
        print("=" * 70)

        # Extract ALL domains
        print("[*] Extracting ALL domains...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        time.sleep(1)
        # Match ALL domain patterns in the email
        domain_input.send_keys(r'[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(4)
        
        # Check what was extracted
        check_js = """return document.getElementById('selected-domains-list').textContent;"""
        domains = driver.execute_script(check_js)
        print(f"[+] Domains extracted: {domains[:200]}...")

        # Extract ALL IPs
        print("[*] Extracting ALL IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        time.sleep(1)
        ip_input.send_keys(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(4)
        
        ips = driver.execute_script("""return document.getElementById('selected-ips-list').textContent;""")
        print(f"[+] IPs extracted: {ips[:200]}...")

        # Extract ALL URLs
        print("[*] Extracting ALL URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        time.sleep(1)
        url_input.send_keys(r'https?://[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        
        urls = driver.execute_script("""return document.getElementById('selected-urls-list').textContent;""")
        print(f"[+] URLs extracted: {urls[:200]}...")

        # Extract ALL Emails
        print("[*] Extracting ALL emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        time.sleep(1)
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(4)
        
        emails = driver.execute_script("""return document.getElementById('selected-emails-list').textContent;""")
        print(f"[+] Emails extracted: {emails[:200]}...\n")

        # STEP 2: Switch to Defang tab
        print("[*] Switching to Defang & Report tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)
        print("[+] On Defang & Report tab\n")

        # STEP 3: Enter SED
        print("=" * 70)
        print("STEP 3: Entering SED command")
        print("=" * 70 + "\n")

        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(2)
        
        # Full SED with all replacements
        sed_cmd = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[:\/\/]/g'
        print(f"[*] Entering SED: {sed_cmd}")
        sed_input.send_keys(sed_cmd)
        time.sleep(2)
        
        print("[*] Clicking Apply...")
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        time.sleep(15)
        print("[+] SED applied\n")

        # Check defanged results
        check_js = """
        const list = document.getElementById('defanged-list');
        if (list) {
            return {
                text: list.textContent.substring(0, 1500),
                count: list.querySelectorAll('.ioc-item').length
            };
        }
        return { text: 'not found', count: 0 };
        """
        result = driver.execute_script(check_js)
        print("=" * 70)
        print("DEFANGED IOCs")
        print("=" * 70)
        print(f"[*] Count: {result['count']}")
        print(f"[*] Preview:\n{result['text']}\n")

        # STEP 4: Submit
        print("=" * 70)
        print("STEP 4: Submitting")
        print("=" * 70 + "\n")
        
        print("[*] Clicking Send to Security Team...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked Send")
        time.sleep(20)

        # Check result
        alert_js = """const alert = document.getElementById('alert'); return alert ? alert.textContent : 'no alert';"""
        alert_text = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert_text}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_manual_result.png")

        # Verify
        print("=" * 70)
        print("STEP 5: Verifying")
        print("=" * 70 + "\n")
        
        driver.switch_to.default_content()
        
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(5)
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
            print("[!] Not complete yet")
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
