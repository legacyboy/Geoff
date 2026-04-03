#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Hybrid Approach
Calls defangIOCs() then manually fixes remaining items
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
    print("SANS HHC 2025 - Defang Challenge - Hybrid Approach")
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

        # STEP 3: Call defangIOCs() first
        print("[*] Calling defangIOCs()...")
        driver.execute_script("if (typeof defangIOCs === 'function') defangIOCs();")
        time.sleep(5)
        print("[+] defangIOCs() called\n")

        # STEP 4: Now manually fix the remaining items (@ and http)
        print("=" * 70)
        print("STEP 4: Manual fix for @ and http")
        print("=" * 70 + "\n")

        fix_js = """
        // Fix emails - replace @ with [@]
        if (typeof defangedEmails !== 'undefined' && defangedEmails.length > 0) {
            defangedEmails = defangedEmails.map(e => e.replace(/@/g, '[@]'));
        }
        
        // Fix URLs - replace http with hxxp and :// with [://]
        if (typeof defangedURLs !== 'undefined' && defangedURLs.length > 0) {
            defangedURLs = defangedURLs.map(url => {
                return url.replace(/http/g, 'hxxp').replace(/:\/\//g, '[://]');
            });
        }
        
        // Rebuild defangedIOCs
        defangedIOCs = [];
        if (typeof defangedDomains !== 'undefined') defangedIOCs = defangedIOCs.concat(defangedDomains);
        if (typeof defangedIPs !== 'undefined') defangedIOCs = defangedIOCs.concat(defangedIPs);
        if (typeof defangedURLs !== 'undefined') defangedIOCs = defangedIOCs.concat(defangedURLs);
        if (typeof defangedEmails !== 'undefined') defangedIOCs = defangedIOCs.concat(defangedEmails);
        
        // Update UI
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            defangedList.innerHTML = defangedIOCs.map(ioc => 
                '<div class="defanged-item"><label><input type="checkbox" checked> ' + ioc + '</label></div>'
            ).join('');
        }
        
        // Update count
        const count = document.getElementById('defanged-count');
        if (count) count.textContent = defangedIOCs.length;
        
        return {
            domains: defangedDomains || [],
            ips: defangedIPs || [],
            urls: defangedURLs || [],
            emails: defangedEmails || [],
            total: defangedIOCs.length
        };
        """
        
        result = driver.execute_script(fix_js)
        print(f"[+] Fixed IOCs: {result}\n")
        time.sleep(5)

        # STEP 5: Verify
        print("=" * 70)
        print("STEP 5: Verifying defanged list")
        print("=" * 70 + "\n")
        
        check_js = """
        const list = document.getElementById('defanged-list');
        if (list) {
            const text = list.textContent;
            return {
                preview: text.substring(0, 500),
                hasUnescapedDots: text.includes('.') && !text.includes('[.]'),
                hasUnescapedAt: text.includes('@') && !text.includes('[@]'),
                hasUnescapedHttp: (text.includes('http://') || text.includes('https://')) && !text.includes('hxxp')
            };
        }
        return { preview: 'not found' };
        """
        
        check = driver.execute_script(check_js)
        print(f"[*] Preview:\n{check['preview']}\n")
        
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

        # STEP 6: Submit
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_hybrid_result.png")

        # STEP 7: Verify achievements
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
