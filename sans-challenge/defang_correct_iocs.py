#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - CORRECT IOCS
Only extracts malicious IOCs (icicleinnovations.*), not victim infrastructure
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
    print("SANS HHC 2025 - Defang Challenge - CORRECT IOCS")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login and open terminal
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
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
            print("[+] CTF mode enabled")
        except:
            pass

        print("[*] Opening defang terminal...")
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
        
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        time.sleep(10)
        
        # Extract ONLY malicious IOCs
        print("=" * 70)
        print("STEP 6: Extracting ONLY malicious IOCs")
        print("=" * 70 + "\n")
        
        # Domain: icicleinnovations.mail (NOT dosisneighborhood.corp)
        print("[*] Extracting domain (icicleinnovations.mail only)...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'icicleinnovations\.mail')
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(2)
        
        # IPs: 172.16.254.1, 192.168.1.1 (NOT 10.0.0.5 which is victim infrastructure)
        print("[*] Extracting IPs (only attacker IPs)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(1)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        # Match 172.16.254.x and 192.168.1.x (attacker), NOT 10.0.0.x (victim)
        ip_input.send_keys(r'172\.16\.254\.[0-9]+|192\.168\.[0-9]+\.[0-9]+')
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(2)
        
        # URLs: https://icicleinnovations.mail/* (NOT victim URLs)
        print("[*] Extracting URLs (attacker URLs only)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(1)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https?://icicleinnovations\.mail/[^\s]+')
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(2)
        
        # Emails: sales@icicleinnovations.mail (NOT victim emails)
        print("[*] Extracting emails (attacker emails only)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(1)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'sales@icicleinnovations\.mail|info@icicleinnovations\.mail')
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(2)
        
        print("[+] Malicious IOCs extracted\n")
        
        # Switch to Defang tab
        print("[*] Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(5)
        print("[+] On Defang tab\n")
        
        # Use SED to defang
        print("[*] Applying SED defang command...")
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        sed_command = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g'
        sed_input.send_keys(sed_command)
        print(f"[*] SED command: {sed_command}")
        
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        print("[+] Applied SED command")
        time.sleep(5)
        
        # Verify
        check_js = """
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            const items = defangedList.querySelectorAll('.defanged-item');
            return {
                itemCount: items.length,
                preview: defangedList.textContent.substring(0, 400)
            };
        }
        return { itemCount: 0 };
        """
        
        check = driver.execute_script(check_js)
        print(f"[*] Defanged items: {check['itemCount']}")
        print(f"[*] Preview: {check['preview']}\n")
        
        # Submit
        print("[*] Submitting to Security Team...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(15)
        
        # Check result
        alert_js = """
        const alertBox = document.getElementById('alert');
        return alertBox ? alertBox.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")
        
        # Verify in achievements
        print("[*] Verifying completion...")
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
            print("\n[!] Not in achievements")
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
