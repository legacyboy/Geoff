#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Working Solution v2
Simplified JavaScript approach
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
    print("SANS HHC 2025 - Terminal 2: Working Solution v2")
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
        
        # === EXTRACT IOCS ===
        print("=" * 70)
        print("STEP 1: Extract IOCs")
        print("=" * 70 + "\n")
        
        # Extract via form submission
        patterns = {
            'domain': r"[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+",
            'ip': r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            'url': r"https?://[^\s\"]+",
            'email': r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        }
        
        for ioc_type, pattern in patterns.items():
            print(f"  [*] Extracting {ioc_type}s...")
            driver.find_element(By.XPATH, f"//button[@data-ioc-type='{ioc_type}s']").click()
            time.sleep(2)
            driver.find_element(By.ID, f"{ioc_type}-regex").clear()
            driver.find_element(By.ID, f"{ioc_type}-regex").send_keys(pattern)
            driver.find_element(By.ID, f"{ioc_type}-form").find_element(By.TAG_NAME, "button").click()
            time.sleep(3)
            print(f"    [+] {ioc_type}s extracted")
        
        print("\n[+] IOCs extracted\n")
        
        # Go to Defang tab
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang tab\n")
        
        # === DEFANG ===
        print("=" * 70)
        print("STEP 2: Defang")
        print("=" * 70 + "\n")
        
        # Use JavaScript to populate arrays and defang
        defang_js = """
        // Get email content
        const emlContent = document.getElementById('eml-content').textContent;
        
        // Extract and populate arrays
        selectedDomains = [...emlContent.matchAll(/[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+/g)].map(m => m[0]);
        selectedIPs = [...emlContent.matchAll(/\\b\\d{1,3}\.\\d{1,3}\.\\d{1,3}\.\\d{1,3}\\b/g)].map(m => m[0]);
        selectedURLs = [...emlContent.matchAll(/https?:\\/\\/[^\\s]+/g)].map(m => m[0]);
        selectedEmails = [...emlContent.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)].map(m => m[0]);
        
        // Defang
        defangedDomains = selectedDomains.map(d => d.replace(/\\./g, '[.]'));
        defangedIPs = selectedIPs.map(ip => ip.replace(/\\./g, '[.]'));
        defangedURLs = selectedURLs.map(url => url.replace(/http/g, 'hxxp').replace(/:\/\\//g, '[://]'));
        defangedEmails = selectedEmails.map(e => e.replace(/@/g, '[@]').replace(/\\./g, '[.]'));
        
        // Combine
        defangedIOCs = [...defangedDomains, ...defangedIPs, ...defangedURLs, ...defangedEmails];
        
        // Update display directly
        if (defangedList) {
            defangedList.innerHTML = defangedIOCs.map(ioc => '<div class="defanged-item">' + ioc + '</div>').join('');
        }
        
        // Update count
        if (defangedCountBadge) {
            defangedCountBadge.textContent = defangedIOCs.length;
        }
        
        return {
            extracted: {
                domains: selectedDomains.length,
                ips: selectedIPs.length,
                urls: selectedURLs.length,
                emails: selectedEmails.length
            },
            defanged: defangedIOCs.length
        };
        """
        
        result = driver.execute_script(defang_js)
        print(f"[+] JavaScript result: {result}")
        time.sleep(3)
        
        # Check defanged list
        defanged = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list: {defanged[:500]}")
        
        # === SUBMIT ===
        print("\n" + "=" * 70)
        print("STEP 3: Send to Security Team")
        print("=" * 70 + "\n")
        
        driver.find_element(By.ID, "send-iocs").click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(10)
        
        # Check alert
        try:
            alert = driver.find_element(By.ID, "alert").text
            print(f"[*] Alert: {alert}")
        except:
            print("[!] No alert")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_v2_result.png")
        
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
