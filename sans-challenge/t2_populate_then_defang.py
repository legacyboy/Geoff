#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Populate arrays then defang
First populate JS arrays, then call defangIOCs()
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
    print("SANS HHC 2025 - Terminal 2: Populate Arrays Then Defang")
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
        
        time.sleep(10)
        
        # === POPULATE JS ARRAYS ===
        print("=" * 70)
        print("STEP 1: Populate JavaScript arrays")
        print("=" * 70 + "\n")
        
        populate_js = """
        const emlContent = document.getElementById('eml-content').textContent;
        
        // Extract and populate arrays with UNIQUE values only
        const domainMatches = [...emlContent.matchAll(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/g)].map(m => m[0]);
        selectedDomains = [...new Set(domainMatches)].filter(d => d.includes('.'));
        
        const ipMatches = [...emlContent.matchAll(/\\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\\b/g)].map(m => m[0]);
        selectedIPs = [...new Set(ipMatches)];
        
        const urlMatches = [...emlContent.matchAll(/https?:\\/\\/[^\\s]+/g)].map(m => m[0]);
        selectedURLs = [...new Set(urlMatches)];
        
        const emailMatches = [...emlContent.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)].map(m => m[0]);
        selectedEmails = [...new Set(emailMatches)];
        
        // Update displays
        const domainList = document.getElementById('selected-domains-list');
        const ipList = document.getElementById('selected-ips-list');
        const urlList = document.getElementById('selected-urls-list');
        const emailList = document.getElementById('selected-emails-list');
        
        if (domainList) domainList.innerHTML = selectedDomains.map(d => '<div class="ioc-item"><label><input type="checkbox" checked> ' + d + '</label></div>').join('');
        if (ipList) ipList.innerHTML = selectedIPs.map(ip => '<div class="ioc-item"><label><input type="checkbox" checked> ' + ip + '</label></div>').join('');
        if (urlList) urlList.innerHTML = selectedURLs.map(url => '<div class="ioc-item"><label><input type="checkbox" checked> ' + url + '</label></div>').join('');
        if (emailList) emailList.innerHTML = selectedEmails.map(e => '<div class="ioc-item"><label><input type="checkbox" checked> ' + e + '</label></div>').join('');
        
        // Update counts
        const domainCount = document.getElementById('domain-count');
        const ipCount = document.getElementById('ip-count');
        const urlCount = document.getElementById('url-count');
        const emailCount = document.getElementById('email-count');
        
        if (domainCount) domainCount.textContent = selectedDomains.length;
        if (ipCount) ipCount.textContent = selectedIPs.length;
        if (urlCount) urlCount.textContent = selectedURLs.length;
        if (emailCount) emailCount.textContent = selectedEmails.length;
        
        return {
            domains: selectedDomains.length,
            ips: selectedIPs.length,
            urls: selectedURLs.length,
            emails: selectedEmails.length
        };
        """
        
        result = driver.execute_script(populate_js)
        print(f"[+] Populated: {result}")
        time.sleep(3)
        
        # Go to Defang tab
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang tab\n")
        
        # === DEFANG ===
        print("=" * 70)
        print("STEP 2: Defang using defangIOCs()")
        print("=" * 70 + "\n")
        
        # Call defangIOCs() with chained SED commands
        defang_js = """
        // Set SED to chain all replacements
        document.getElementById('defang-sed').value = "s/\\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\\/\\//[://]/g";
        
        // Call defangIOCs
        defangIOCs();
        
        return 'defangIOCs() called';
        """
        
        result = driver.execute_script(defang_js)
        print(f"[+] {result}")
        time.sleep(5)
        
        # Check defanged list
        check_js = """
        const defangedList = document.getElementById('defanged-list');
        return {
            html: defangedList ? defangedList.innerHTML.substring(0, 500) : 'not found',
            text: defangedList ? defangedList.textContent.substring(0, 500) : 'not found',
            count: defangedIOCs ? defangedIOCs.length : 0
        };
        """
        
        check = driver.execute_script(check_js)
        print(f"\n[*] Defanged list: {check['text'][:300]}")
        print(f"[*] Defanged count: {check['count']}")
        
        # === SUBMIT ===
        print("\n" + "=" * 70)
        print("STEP 3: Send to Security Team")
        print("=" * 70 + "\n")
        
        driver.find_element(By.ID, "send-iocs").click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(10)
        
        # Check alert
        alert_js = """
        const alertBox = document.getElementById('alert');
        return alertBox ? alertBox.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_populate_result.png")
        
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
