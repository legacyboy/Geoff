#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Exact SED Approach
Uses the exact SED format: s/\./[.]/g; s/@/[@]/g; s/http/hxxp/g
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
    print("SANS HHC 2025 - Defang Challenge - Exact SED Approach")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login and navigate
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

        # STEP 1: Extract IOCs
        print("\n" + "=" * 70)
        print("STEP 1: Extracting IOCs")
        print("=" * 70)

        # Extract Domains
        print("[*] Extracting domains...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Domains extracted")

        # Extract IPs
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.[0-9]+\.[0-9]+\.[0-9]+|192\.[0-9]+\.[0-9]+\.[0-9]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(4)
        print("[+] IPs extracted")

        # Extract URLs - ONLY attacker URLs (icicleinnovations.mail)
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        # Only match URLs containing icicleinnovations.mail
        url_input.send_keys(r'https?://icicleinnovations\.mail/[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        print("[+] URLs extracted")

        # Extract Emails
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Emails extracted\n")

        # STEP 2: Switch to Defang & Report tab
        print("[*] Switching to Defang & Report tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)
        print("[+] On Defang & Report tab\n")

        # STEP 3: Enter SED command and Apply
        print("=" * 70)
        print("STEP 3: Entering SED command and Applying")
        print("=" * 70 + "\n")

        print("[*] Finding SED input field...")
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(2)
        
        # Enter the exact SED command
        # Also need to replace :// with [://] for URLs
        sed_cmd = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[:\/\/]/g'
        print(f"[*] Entering SED: {sed_cmd}")
        sed_input.send_keys(sed_cmd)
        time.sleep(2)
        
        print("[*] Clicking Apply button...")
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        time.sleep(15)
        print("[+] SED command applied\n")

        # STEP 4: Check the defanged list
        print("=" * 70)
        print("STEP 4: Checking defanged list")
        print("=" * 70 + "\n")
        
        check_js = """
        const list = document.getElementById('defanged-list');
        if (list) {
            const text = list.textContent;
            return {
                preview: text.substring(0, 600),
                hasUnescapedDots: text.includes('.') && !text.includes('[.]'),
                hasUnescapedAt: text.includes('@') && !text.includes('[@]'),
                hasUnescapedHttp: (text.includes('http://') || text.includes('https://')) && !text.includes('hxxp')
            };
        }
        return { preview: 'not found' };
        """
        
        result = driver.execute_script(check_js)
        print(f"[*] Preview:\n{result['preview']}\n")
        
        if result.get('hasUnescapedDots'):
            print("[!] Still has unescaped dots")
        if result.get('hasUnescapedAt'):
            print("[!] Still has unescaped @")
        if result.get('hasUnescapedHttp'):
            print("[!] Still has unescaped http")

        # STEP 5: Click Send to Security Team
        print("\n" + "=" * 70)
        print("STEP 5: Sending to Security Team")
        print("=" * 70 + "\n")
        
        print("[*] Clicking Send to Security Team...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked Send to Security Team")
        time.sleep(20)

        # Check result
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? alert.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_sed_exact_result.png")

        # STEP 6: Verify in achievements
        print("=" * 70)
        print("STEP 6: Verifying completion")
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
            print("\n[!] Not in achievements yet")
            print("[*] Achievements text:")
            print(text[:500])
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
