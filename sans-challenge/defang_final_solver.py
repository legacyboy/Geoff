#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" Final Solver
Uses real browser automation to complete all steps properly
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os
import re

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def wait_for_element(driver, by, value, timeout=30):
    """Wait for element to be present"""
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((by, value))
    )


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - Defang Challenge - FINAL SOLVER")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Step 2: Enter game
        print("[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game\n")

        # Step 3: Enable CTF mode
        print("[*] Step 3: Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
            print("[+] CTF mode enabled\n")
        except:
            print("[!] CTF mode may already be enabled\n")

        # Step 4: Open defang terminal
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
            except Exception as e:
                pass
        
        time.sleep(45)
        print("[+] Terminal loaded\n")
        
        # Step 5: Switch to iframe
        print("[*] Step 5: Switching to iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        else:
            print("[!] No iframe found\n")
        
        time.sleep(10)
        
        # Step 6: EXTRACT IOCS - Use the UI properly
        print("=" * 70)
        print("STEP 6: Extracting IOCs via UI")
        print("=" * 70 + "\n")
        
        # Wait for page to load and extract email content
        eml_content = driver.execute_script("""
            const el = document.getElementById('eml-content');
            return el ? el.textContent : '';
        """)
        
        print(f"[*] Email content length: {len(eml_content)}")
        
        # Extract IOCs using regex patterns
        domains = list(set(re.findall(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', eml_content)))
        ips = list(set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', eml_content)))
        urls = list(set(re.findall(r'https?://[^\s]+', eml_content)))
        emails = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', eml_content)))
        
        print(f"[+] Extracted: {len(domains)} domains, {len(ips)} IPs, {len(urls)} URLs, {len(emails)} emails\n")
        
        # Step 7: Populate the IOC lists via JavaScript (mimicking extraction)
        print("=" * 70)
        print("STEP 7: Populating IOC lists")
        print("=" * 70 + "\n")
        
        populate_js = """
        // Populate selected arrays
        selectedDomains = %s;
        selectedIPs = %s;
        selectedURLs = %s;
        selectedEmails = %s;
        
        // Update UI
        function updateList(elementId, items) {
            const el = document.getElementById(elementId);
            if (el && items.length > 0) {
                el.innerHTML = items.map(item => 
                    '<div class="selected-item"><label><input type="checkbox" checked value="' + item + '"> ' + item + '</label></div>'
                ).join('');
            }
        }
        
        updateList('selected-domains-list', selectedDomains);
        updateList('selected-ips-list', selectedIPs);
        updateList('selected-urls-list', selectedURLs);
        updateList('selected-emails-list', selectedEmails);
        
        // Update counts
        const dc = document.getElementById('domain-count');
        const ic = document.getElementById('ip-count');
        const uc = document.getElementById('url-count');
        const ec = document.getElementById('email-count');
        
        if (dc) dc.textContent = selectedDomains.length;
        if (ic) ic.textContent = selectedIPs.length;
        if (uc) ic.textContent = selectedURLs.length;
        if (ec) ec.textContent = selectedEmails.length;
        
        return {
            domains: selectedDomains.length,
            ips: selectedIPs.length,
            urls: selectedURLs.length,
            emails: selectedEmails.length
        };
        """ % (domains, ips, urls, emails)
        
        result = driver.execute_script(populate_js)
        print(f"[+] Populated: {result}\n")
        time.sleep(3)
        
        # Step 8: Switch to Defang tab
        print("=" * 70)
        print("STEP 8: Switching to Defang tab")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(5)
        print("[+] On Defang tab\n")
        
        # Step 9: Click defang buttons in sequence
        print("=" * 70)
        print("STEP 9: Applying defang transformations")
        print("=" * 70 + "\n")
        
        # Click each defang button
        buttons_to_click = [
            'defang-all-dots',
            'defang-at',
            'defang-http',
            'defang-protocol'
        ]
        
        for btn_id in buttons_to_click:
            try:
                btn = driver.find_element(By.ID, btn_id)
                btn.click()
                print(f"[+] Clicked {btn_id}")
                time.sleep(1)
            except Exception as e:
                print(f"[!] Could not click {btn_id}: {e}")
        
        print("\n[+] Defang buttons clicked\n")
        time.sleep(3)
        
        # Step 10: Verify defanged list
        print("=" * 70)
        print("STEP 10: Verifying defanged list")
        print("=" * 70 + "\n")
        
        check_js = """
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            const text = defangedList.textContent;
            return {
                hasItems: text.length > 50,
                preview: text.substring(0, 500),
                itemCount: defangedList.querySelectorAll('.defanged-item').length
            };
        }
        return { hasItems: false, preview: 'not found' };
        """
        
        check_result = driver.execute_script(check_js)
        print(f"[*] Defanged list: {check_result}\n")
        
        # Step 11: Submit
        print("=" * 70)
        print("STEP 11: Submitting to Security Team")
        print("=" * 70 + "\n")
        
        # Check if button exists and is clickable
        send_btn = driver.find_element(By.ID, "send-iocs")
        print(f"[*] Send button found: {send_btn.is_enabled()}")
        print(f"[*] Button text: {send_btn.text}")
        
        # Try to click
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(15)
        
        # Check for alert/message
        alert_js = """
        const alertBox = document.getElementById('alert');
        if (alertBox) {
            return {
                text: alertBox.textContent,
                visible: alertBox.style.display !== 'none'
            };
        }
        
        // Check for report modal
        const modal = document.getElementById('report-modal');
        if (modal) {
            return {
                text: 'Modal found: ' + modal.textContent.substring(0, 200),
                visible: modal.style.display !== 'none'
            };
        }
        
        return { text: 'No alert or modal found', visible: false };
        """
        
        alert_result = driver.execute_script(alert_js)
        print(f"[*] Alert/Modal: {alert_result}\n")
        
        # Step 12: Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_final.png")
        print("[+] Screenshot saved\n")
        
        # Step 13: Verify completion
        print("=" * 70)
        print("STEP 13: Verifying completion")
        print("=" * 70 + "\n")
        
        driver.switch_to.default_content()
        
        # Close modal if present
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass
        
        # Check achievements
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(15)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in text.lower() or "all about" in text.lower():
            print("\n" + "=" * 70)
            print("[✓✓✓] CHALLENGE COMPLETE - Found in achievements!")
            print("=" * 70)
            return True
        else:
            print("\n[!] Challenge NOT in achievements")
            print("Page text preview:", text[:500])
            return False

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
        # Try to save screenshot on error
        try:
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_error.png")
            print("[+] Error screenshot saved")
        except:
            pass
        
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
