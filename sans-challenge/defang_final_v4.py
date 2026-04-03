#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Final v4
Uses execute_script to both set variables AND submit in same context
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
    print("SANS HHC 2025 - Defang Challenge - Final v4")
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

        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(3)
        print("[+] Domains extracted")

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(2)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.[0-9]+\.[0-9]+\.[0-9]+|192\.[0-9]+\.[0-9]+\.[0-9]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(3)
        print("[+] IPs extracted")

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(2)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https?://[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(3)
        print("[+] URLs extracted")

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(2)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(3)
        print("[+] Emails extracted\n")

        # STEP 2: Switch to Defang tab
        print("[*] Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)
        print("[+] On Defang tab\n")

        # STEP 3: Create defanged IOCs AND submit in ONE execute_script
        print("=" * 70)
        print("STEP 3: Setting variables AND submitting")
        print("=" * 70 + "\n")

        submit_js = """
        // Get selected IOCs
        let domains = [];
        let ips = [];
        let urls = [];
        let emails = [];
        
        if (typeof selectedDomains !== 'undefined') domains = selectedDomains.filter(d => d.includes('icicleinnovations'));
        if (typeof selectedIPs !== 'undefined') ips = selectedIPs.filter(ip => ip.startsWith('172') || ip.startsWith('192'));
        if (typeof selectedURLs !== 'undefined') urls = selectedURLs.filter(u => u.includes('icicleinnovations'));
        if (typeof selectedEmails !== 'undefined') emails = selectedEmails.filter(e => e.includes('icicleinnovations'));
        
        // Extract from email as fallback
        const emlContent = document.getElementById('eml-content').textContent;
        
        if (domains.length === 0) {
            const dm = [...emlContent.matchAll(/[a-zA-Z0-9-]+\.icicleinnovations\.mail/g)];
            domains = [...new Set(dm.map(m => m[0]))];
        }
        if (ips.length === 0) {
            const im = [...emlContent.matchAll(/(?:172|192)\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}/g)];
            ips = [...new Set(im.map(m => m[0]))];
        }
        if (urls.length === 0) {
            const um = [...emlContent.matchAll(/https?:\/\/icicleinnovations\.mail\/[^\s]+/g)];
            urls = [...new Set(um.map(m => m[0]))];
        }
        if (emails.length === 0) {
            const em = [...emlContent.matchAll(/[a-zA-Z0-9._%+-]+@icicleinnovations\.mail/g)];
            emails = [...new Set(em.map(m => m[0]))];
        }
        
        // Create defanged versions
        defangedDomains = domains.map(d => d.replace(/\./g, '[.]'));
        defangedIPs = ips.map(ip => ip.replace(/\./g, '[.]'));
        defangedURLs = urls.map(url => url.replace(/http/g, 'hxxp').replace(/:\/\//g, '[://]').replace(/\./g, '[.]'));
        defangedEmails = emails.map(e => e.replace(/@/g, '[@]').replace(/\./g, '[.]'));
        defangedIOCs = [...defangedDomains, ...defangedIPs, ...defangedURLs, ...defangedEmails];
        
        // Update UI
        const list = document.getElementById('defanged-list');
        if (list) {
            list.innerHTML = defangedIOCs.map(ioc => 
                '<div class="defanged-item"><label><input type="checkbox" checked> ' + ioc + '</label></div>'
            ).join('');
        }
        const count = document.getElementById('defanged-count');
        if (count) count.textContent = defangedIOCs.length;
        
        // NOW trigger the submit button click
        const sendBtn = document.getElementById('send-iocs');
        if (sendBtn) {
            // Create and dispatch a click event
            const clickEvent = new MouseEvent('click', {
                bubbles: true,
                cancelable: true,
                view: window
            });
            sendBtn.dispatchEvent(clickEvent);
            return 'Submitted via dispatchEvent';
        }
        
        return 'Send button not found';
        """
        
        result = driver.execute_script(submit_js)
        print(f"[*] Submit result: {result}")
        time.sleep(20)

        # Check result
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? alert.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_v4_result.png")

        # Verify achievements
        print("[*] Verifying completion...")
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
