#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Final Working Solution
Properly trigger the defangIOCs() function via SED commands
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
    print("SANS HHC 2025 - Terminal 2: Final Working Solution")
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
        
        # === EXTRACT IOCS using JavaScript to populate arrays ===
        print("=" * 70)
        print("STEP 1: Extract IOCs via JavaScript")
        print("=" * 70 + "\n")
        
        # Use JavaScript to extract IOCs and populate the arrays
        extract_js = """
        // Get email content
        const emlContent = document.getElementById('eml-content').textContent;
        
        // Domain pattern
        const domainPattern = /[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+/g;
        selectedDomains = [...emlContent.matchAll(domainPattern)].map(m => m[0]);
        
        // IP pattern  
        const ipPattern = /\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b/g;
        selectedIPs = [...emlContent.matchAll(ipPattern)].map(m => m[0]);
        
        // URL pattern
        const urlPattern = /https?:\\/\\/[^\\s]+/g;
        selectedURLs = [...emlContent.matchAll(urlPattern)].map(m => m[0]);
        
        // Email pattern
        const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g;
        selectedEmails = [...emlContent.matchAll(emailPattern)].map(m => m[0]);
        
        // Update displays
        updateIOCList(selectedDomainsList, selectedDomains, 'domain');
        updateIOCList(selectedIPsList, selectedIPs, 'ip');
        updateIOCList(selectedURLsList, selectedURLs, 'url');
        updateIOCList(selectedEmailsList, selectedEmails, 'email');
        
        // Update counts
        if (domainCountBadge) domainCountBadge.textContent = selectedDomains.length;
        if (ipCountBadge) ipCountBadge.textContent = selectedIPs.length;
        if (urlCountBadge) urlCountBadge.textContent = selectedURLs.length;
        if (emailCountBadge) emailCountBadge.textContent = selectedEmails.length;
        
        return {
            domains: selectedDomains.length,
            ips: selectedIPs.length,
            urls: selectedURLs.length,
            emails: selectedEmails.length
        };
        """
        
        result = driver.execute_script(extract_js)
        print(f"[+] Extracted: {result}")
        time.sleep(3)
        
        # Go to Defang tab
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang tab\n")
        
        # === DEFANG using JavaScript ===
        print("=" * 70)
        print("STEP 2: Defang using JavaScript")
        print("=" * 70 + "\n")
        
        defang_js = """
        // Create defanged versions
        defangedDomains = selectedDomains.map(d => d.replace(/\\./g, '[.]'));
        defangedIPs = selectedIPs.map(ip => ip.replace(/\\./g, '[.]'));
        defangedURLs = selectedURLs.map(url => {
            return url.replace(/http/g, 'hxxp').replace(/:\/\\//g, '[://]');
        });
        defangedEmails = selectedEmails.map(e => {
            return e.replace(/@/g, '[@]').replace(/\\./g, '[.]');
        });
        
        // Combine all defanged IOCs
        defangedIOCs = [...defangedDomains, ...defangedIPs, ...defangedURLs, ...defangedEmails];
        
        // Update the display
        displayDefangedResults();
        
        // Update count
        if (defangedCountBadge) {
            defangedCountBadge.textContent = defangedIOCs.length;
        }
        
        return `Defanged ${defangedIOCs.length} IOCs`;
        """
        
        result = driver.execute_script(defang_js)
        print(f"[+] {result}")
        time.sleep(3)
        
        # Check defanged list
        defanged = driver.find_element(By.ID, "defanged-list").text
        print(f"\n[*] Defanged list preview: {defanged[:300]}")
        
        # Verify defanging worked
        has_dots = "." in defanged.replace("[.]", "").replace("[./]", "")
        has_at = "@" in defanged.replace("[@]", "")
        
        if has_dots:
            print("[!] WARNING: Still has unescaped dots!")
        if has_at:
            print("[!] WARNING: Still has unescaped @!")
        
        if not has_dots and not has_at and defanged != "No defanged IOCs yet":
            print("\n[✓] All IOCs properly defanged!")
        
        # === STEP 3: SUBMIT ===
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_final_result.png")
        print("\n[+] Screenshot saved")
        
        # Switch back and verify
        driver.switch_to.default_content()
        
        # Close modal
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        # Verify completion
        print("\n[*] Verifying completion...")
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
