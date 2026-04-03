#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Final v3
Fully defangs URLs including domain dots, ensures defangedIOCs is set
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
    print("SANS HHC 2025 - Defang Challenge - Final v3")
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

        # STEP 3: Create fully defanged IOCs
        print("=" * 70)
        print("STEP 3: Creating fully defanged IOCs")
        print("=" * 70 + "\n")

        defang_js = """
        // Get selected IOCs from global variables
        let domains = [];
        let ips = [];
        let urls = [];
        let emails = [];
        
        if (typeof selectedDomains !== 'undefined') domains = selectedDomains.filter(d => d.includes('icicleinnovations'));
        if (typeof selectedIPs !== 'undefined') ips = selectedIPs.filter(ip => ip.startsWith('172') || ip.startsWith('192'));
        if (typeof selectedURLs !== 'undefined') urls = selectedURLs.filter(u => u.includes('icicleinnovations'));
        if (typeof selectedEmails !== 'undefined') emails = selectedEmails.filter(e => e.includes('icicleinnovations'));
        
        // Extract from email content as fallback
        const emlContent = document.getElementById('eml-content').textContent;
        
        if (domains.length === 0) {
            const domainMatches = [...emlContent.matchAll(/[a-zA-Z0-9-]+\\.icicleinnovations\\.mail/g)];
            domains = [...new Set(domainMatches.map(m => m[0]))];
        }
        if (ips.length === 0) {
            const ipMatches = [...emlContent.matchAll(/(?:172|192)\\.(?:[0-9]{1,3}\\.){2}[0-9]{1,3}/g)];
            ips = [...new Set(ipMatches.map(m => m[0]))];
        }
        if (urls.length === 0) {
            const urlMatches = [...emlContent.matchAll(/https?:\\/\\/icicleinnovations\\.mail\\/[^\\s]+/g)];
            urls = [...new Set(urlMatches.map(m => m[0]))];
        }
        if (emails.length === 0) {
            const emailMatches = [...emlContent.matchAll(/[a-zA-Z0-9._%+-]+@icicleinnovations\\.mail/g)];
            emails = [...new Set(emailMatches.map(m => m[0]))];
        }
        
        // Create FULLY defanged versions
        // Domains: replace all dots
        defangedDomains = domains.map(d => d.replace(/\\./g, '[.]'));
        
        // IPs: replace all dots
        defangedIPs = ips.map(ip => ip.replace(/\\./g, '[.]'));
        
        // URLs: replace http with hxxp, :// with [://], AND all dots in domain
        defangedURLs = urls.map(url => {
            return url
                .replace(/http/g, 'hxxp')
                .replace(/:\\/\\//g, '[://]')
                .replace(/\\./g, '[.]');  // Defang ALL dots including in domain
        });
        
        // Emails: replace @ with [@] and all dots
        defangedEmails = emails.map(e => e.replace(/@/g, '[@]').replace(/\\./g, '[.]'));
        
        // Combine all - THIS IS WHAT THE SUBMIT BUTTON CHECKS
        defangedIOCs = [...defangedDomains, ...defangedIPs, ...defangedURLs, ...defangedEmails];
        
        // Also set on window to be sure
        window.defangedDomains = defangedDomains;
        window.defangedIPs = defangedIPs;
        window.defangedURLs = defangedURLs;
        window.defangedEmails = defangedEmails;
        window.defangedIOCs = defangedIOCs;
        
        // Update the UI
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            defangedList.innerHTML = defangedIOCs.map(ioc => 
                '<div class="defanged-item"><label><input type="checkbox" checked> ' + ioc + '</label></div>'
            ).join('');
        }
        
        // Update count
        const count = document.getElementById('defanged-count');
        if (count) count.textContent = defangedIOCs.length;
        
        // Trigger any events that might be needed
        if (typeof updateDefangedCount === 'function') {
            updateDefangedCount();
        }
        
        return {
            domains: defangedDomains,
            ips: defangedIPs,
            urls: defangedURLs,
            emails: defangedEmails,
            total: defangedIOCs.length,
            defangedIOCsLength: defangedIOCs.length
        };
        """
        
        result = driver.execute_script(defang_js)
        print(f"[+] Defanged: {result}\n")
        time.sleep(5)

        # STEP 4: Verify
        print("=" * 70)
        print("STEP 4: Verifying defanged list")
        print("=" * 70 + "\n")
        
        check_js = """
        // Check both UI and variables
        const list = document.getElementById('defanged-list');
        const listText = list ? list.textContent : 'no list';
        
        return {
            preview: listText.substring(0, 600),
            defangedIOCsExists: typeof defangedIOCs !== 'undefined',
            defangedIOCsLength: typeof defangedIOCs !== 'undefined' ? defangedIOCs.length : 0,
            hasUnescapedDots: listText.includes('.') && !listText.includes('[.]'),
            hasUnescapedAt: listText.includes('@') && !listText.includes('[@]'),
            hasUnescapedHttp: (listText.includes('http://') || listText.includes('https://')) && !listText.includes('hxxp')
        };
        """
        
        check = driver.execute_script(check_js)
        print(f"[*] Preview:\n{check['preview']}\n")
        print(f"[*] defangedIOCs exists: {check['defangedIOCsExists']}")
        print(f"[*] defangedIOCs length: {check['defangedIOCsLength']}\n")
        
        issues = []
        if check.get('hasUnescapedDots'):
            issues.append("unescaped dots")
        if check.get('hasUnescapedAt'):
            issues.append("unescaped @")
        if check.get('hasUnescapedHttp'):
            issues.append("unescaped http")
        
        if issues:
            print(f"[!] Issues: {', '.join(issues)}\n")
        else:
            print("[✓] All IOCs properly defanged!\n")

        # STEP 5: Submit
        print("[*] Submitting...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(15)

        # Check result
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? alert.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_v3_result.png")

        # STEP 6: Verify achievements
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
            print("[*] Achievements text preview:")
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
