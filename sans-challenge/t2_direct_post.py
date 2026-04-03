#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Direct POST to /send_iocs
Bypass the UI and submit directly via fetch API
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
    print("SANS HHC 2025 - Terminal 2: Direct POST")
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
        
        # === BUILD DEFANGED IOCS AND POST ===
        print("=" * 70)
        print("STEP 1: Build and submit via fetch")
        print("=" * 70 + "\n")
        
        post_js = r"""
        const emlContent = document.getElementById('eml-content').textContent;
        
        // Extract
        const domains = [...new Set([...emlContent.matchAll(/[a-zA-Z0-9-]+\.[a-zA-Z]{2,}/g)].map(m => m[0]))];
        const ips = [...new Set([...emlContent.matchAll(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g)].map(m => m[0]))];
        const urls = [...new Set([...emlContent.matchAll(/https?:\/\/[^\s]+/g)].map(m => m[0]))];
        const emails = [...new Set([...emlContent.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g)].map(m => m[0]))];
        
        // Defang - replace ALL dots in URLs too
        const defangedDomains = domains.map(d => d.replace(/\./g, '[.]'));
        const defangedIPs = ips.map(ip => ip.replace(/\./g, '[.]'));
        const defangedURLs = urls.map(url => url.replace(/http/g, 'hxxp').replace(/:\/\//g, '[://]').replace(/\./g, '[.]'));
        const defangedEmails = emails.map(e => e.replace(/@/g, '[@]').replace(/\./g, '[.]'));
        
        // Combine
        const defangedIOCs = [...defangedDomains, ...defangedIPs, ...defangedURLs, ...defangedEmails];
        
        // Make POST request
        return fetch('/send_iocs', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ iocs: defangedIOCs })
        }).then(response => response.json()).then(data => {
            return JSON.stringify(data);
        }).catch(err => {
            return 'Error: ' + err.message;
        });
        """
        
        result = driver.execute_script(post_js)
        print(f"[*] POST result: {result}")
        time.sleep(5)
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_post_result.png")
        
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
