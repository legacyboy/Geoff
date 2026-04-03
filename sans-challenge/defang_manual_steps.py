#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Manual UI Steps
Takes time to properly interact with each UI element
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
    print("SANS HHC 2025 - Defang Challenge - Manual UI Steps")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(25)
        print("[+] In game\n")

        # Enable CTF mode
        print("[*] Step 3: Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(8)
        try:
            ctf_btn = driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]")
            ctf_btn.click()
            time.sleep(5)
            print("[+] CTF mode enabled\n")
        except:
            print("[!] CTF mode may already be enabled\n")

        # Open terminal
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
        
        time.sleep(50)  # Wait longer for terminal to load
        print("[+] Terminal loaded\n")
        
        # Switch to iframe
        print("[*] Step 5: Switching to iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        
        time.sleep(10)
        
        # Extract IOCs
        print("=" * 70)
        print("STEP 6: Extracting IOCs")
        print("=" * 70 + "\n")
        
        # Domains tab (already active)
        print("[*] Extracting domains...")
        domain_input = wait.until(EC.presence_of_element_located((By.ID, "domain-regex")))
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        print("[+] Domains extracted")
        time.sleep(3)
        
        # IPs
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.[0-9]+\.[0-9]+\.[0-9]+|192\.[0-9]+\.[0-9]+\.[0-9]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        print("[+] IPs extracted")
        time.sleep(3)
        
        # URLs
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https?://[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        print("[+] URLs extracted")
        time.sleep(3)
        
        # Emails
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        print("[+] Emails extracted")
        time.sleep(3)
        
        print("[+] All IOCs extracted\n")
        
        # Switch to Defang tab
        print("[*] Step 7: Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(8)
        print("[+] On Defang tab\n")
        
        # Use SED
        print("[*] Step 8: Using SED to defang...")
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(1)
        sed_input.send_keys(r's/\./[.]/g')
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        print("[+] Applied dots defang")
        time.sleep(5)
        
        # @ defang
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(1)
        sed_input.send_keys(r's/@/[@]/g')
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        print("[+] Applied @ defang")
        time.sleep(5)
        
        # http defang
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(1)
        sed_input.send_keys(r's/http/hxxp/g')
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        print("[+] Applied http defang")
        time.sleep(5)
        
        print("[+] All defanging applied\n")
        
        # Check defanged list
        check_js = """
        const list = document.getElementById('defanged-list');
        if (list) {
            return {
                count: list.querySelectorAll('.defanged-item').length,
                text: list.textContent.substring(0, 400)
            };
        }
        return { count: 0, text: 'not found' };
        """
        result = driver.execute_script(check_js)
        print(f"[*] Defanged items: {result['count']}")
        print(f"[*] Preview: {result['text']}\n")
        
        # Submit
        print("[*] Step 9: Submitting...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(20)
        
        # Check alert
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? alert.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_step_result.png")
        
        # Verify in achievements
        print("[*] Step 10: Verifying completion...")
        driver.switch_to.default_content()
        
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(5)
        except:
            pass
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(20)
        
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
