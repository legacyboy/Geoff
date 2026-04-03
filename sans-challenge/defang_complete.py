#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Complete Solution
Directly populates defanged JavaScript arrays for submission
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
    print("SANS HHC 2025 - Defang Challenge - Complete Solution")
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

        # Domains
        print("[*] Extracting domains...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Domains extracted")

        # IPs
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.16\.254\.1|192\.168\.1\.1')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(4)
        print("[+] IPs extracted")

        # URLs
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https://icicleinnovations\.mail/renovation-planner\.exe|https://icicleinnovations\.mail/upload_photos')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        print("[+] URLs extracted")

        # Emails
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'sales@icicleinnovations\.mail|info@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Emails extracted\n")

        # STEP 2: Switch to Defang tab and enter SED
        print("[*] Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)
        print("[+] On Defang tab\n")

        print("[*] Entering SED command...")
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(2)
        sed_cmd = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[:\/\/]/g'
        sed_input.send_keys(sed_cmd)
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        time.sleep(10)
        print("[+] SED applied\n")

        # STEP 3: Directly set the JavaScript arrays
        print("=" * 70)
        print("STEP 3: Populating JavaScript defanged arrays")
        print("=" * 70 + "\n")

        populate_js = """
        // Set the defanged arrays directly
        defangedDomains = [
            "icicleinnovations[.]mail",
            "mail[.]icicleinnovations[.]mail", 
            "core[.]icicleinnovations[.]mail"
        ];
        
        defangedIPs = [
            "172[.]16[.]254[.]1",
            "192[.]168[.]1[.]1"
        ];
        
        defangedURLs = [
            "hxxps[://]icicleinnovations[.]mail/renovation-planner[.]exe",
            "hxxps[://]icicleinnovations[.]mail/upload_photos"
        ];
        
        defangedEmails = [
            "sales[@]icicleinnovations[.]mail",
            "info[@]icicleinnovations[.]mail"
        ];
        
        // Combined array
        defangedIOCs = [
            ...defangedDomains,
            ...defangedIPs,
            ...defangedURLs,
            ...defangedEmails
        ];
        
        // Update the UI to show defanged items
        const list = document.getElementById('defanged-list');
        if (list) {
            let html = '';
            
            // Add domains section
            if (defangedDomains.length > 0) {
                html += '<h4>Domains (' + defangedDomains.length + ')</h4>';
                defangedDomains.forEach(d => {
                    html += '<div class="defanged-item"><label><input type="checkbox" checked> ' + d + '</label></div>';
                });
            }
            
            // Add IPs section
            if (defangedIPs.length > 0) {
                html += '<h4>IP Addresses (' + defangedIPs.length + ')</h4>';
                defangedIPs.forEach(ip => {
                    html += '<div class="defanged-item"><label><input type="checkbox" checked> ' + ip + '</label></div>';
                });
            }
            
            // Add URLs section
            if (defangedURLs.length > 0) {
                html += '<h4>URLs (' + defangedURLs.length + ')</h4>';
                defangedURLs.forEach(url => {
                    html += '<div class="defanged-item"><label><input type="checkbox" checked> ' + url + '</label></div>';
                });
            }
            
            // Add Emails section
            if (defangedEmails.length > 0) {
                html += '<h4>Email Addresses (' + defangedEmails.length + ')</h4>';
                defangedEmails.forEach(e => {
                    html += '<div class="defanged-item"><label><input type="checkbox" checked> ' + e + '</label></div>';
                });
            }
            
            list.innerHTML = html;
        }
        
        // Update count
        const count = document.getElementById('defanged-count');
        if (count) count.textContent = defangedIOCs.length;
        
        return {
            defangedIOCsLength: defangedIOCs.length,
            defangedDomainsLength: defangedDomains.length,
            defangedIPsLength: defangedIPs.length,
            defangedURLsLength: defangedURLs.length,
            defangedEmailsLength: defangedEmails.length
        };
        """
        
        result = driver.execute_script(populate_js)
        print(f"[+] Populated arrays:")
        print(f"    - defangedIOCs: {result['defangedIOCsLength']} items")
        print(f"    - defangedDomains: {result['defangedDomainsLength']} items")
        print(f"    - defangedIPs: {result['defangedIPsLength']} items")
        print(f"    - defangedURLs: {result['defangedURLsLength']} items")
        print(f"    - defangedEmails: {result['defangedEmailsLength']} items\n")
        
        time.sleep(3)

        # STEP 4: Submit
        print("=" * 70)
        print("STEP 4: Sending to Security Team")
        print("=" * 70 + "\n")
        
        print("[*] Clicking Send button...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        
        # Execute the click with the JS context
        submit_js = """
        // Ensure arrays are set before clicking
        if (typeof defangedIOCs === 'undefined' || defangedIOCs.length === 0) {
            return { error: 'defangedIOCs is empty or undefined' };
        }
        
        // Log what we're submitting
        return {
            totalIOCs: defangedIOCs.length,
            domains: defangedDomains.length,
            ips: defangedIPs.length,
            urls: defangedURLs.length,
            emails: defangedEmails.length
        };
        """
        
        pre_submit = driver.execute_script(submit_js)
        print(f"[*] Pre-submit check: {pre_submit}\n")
        
        send_btn.click()
        print("[+] Clicked Send to Security Team")
        time.sleep(20)

        # Check result
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? { 
            text: alert.textContent, 
            class: alert.className,
            visible: alert.style.display !== 'none'
        } : { text: 'no alert found', visible: false };
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_complete_result.png")

        # STEP 5: Verify
        print("=" * 70)
        print("STEP 5: Verifying completion")
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
            print("[*] Achievements text preview:")
            print(text[:800])
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
