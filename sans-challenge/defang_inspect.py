#!/usr/bin/env python3
"""
SANS HHC 2025 - Inspect the JavaScript to understand validation
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
    print("SANS HHC 2025 - Defang Challenge - Inspect JavaScript")
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

        # Extract IOCs
        print("\n[*] Extracting IOCs...")
        
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(4)

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.16\.254\.1|192\.168\.1\.1')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(4)

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https://icicleinnovations\.mail/renovation-planner\.exe|https://icicleinnovations\.mail/upload_photos')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)

        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'sales@icicleinnovations\.mail|info@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(4)
        print("[+] IOCs extracted")

        # Switch to defang tab
        print("[*] Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)

        # Enter SED
        print("[*] Entering SED...")
        sed_input = driver.find_element(By.ID, "defang-sed")
        sed_input.clear()
        time.sleep(2)
        sed_cmd = r's/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[:\/\/]/g'
        sed_input.send_keys(sed_cmd)
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        time.sleep(10)
        print("[+] SED applied")

        # Inspect JavaScript variables
        print("\n" + "=" * 70)
        print("INSPECTING JAVASCRIPT VARIABLES")
        print("=" * 70 + "\n")

        inspect_js = """
        const result = {};
        
        // Check all relevant variables
        result.selectedDomains = (typeof selectedDomains !== 'undefined') ? selectedDomains : 'undefined';
        result.selectedIPs = (typeof selectedIPs !== 'undefined') ? selectedIPs : 'undefined';
        result.selectedURLs = (typeof selectedURLs !== 'undefined') ? selectedURLs : 'undefined';
        result.selectedEmails = (typeof selectedEmails !== 'undefined') ? selectedEmails : 'undefined';
        
        result.defangedDomains = (typeof defangedDomains !== 'undefined') ? defangedDomains : 'undefined';
        result.defangedIPs = (typeof defangedIPs !== 'undefined') ? defangedIPs : 'undefined';
        result.defangedURLs = (typeof defangedURLs !== 'undefined') ? defangedURLs : 'undefined';
        result.defangedEmails = (typeof defangedEmails !== 'undefined') ? defangedEmails : 'undefined';
        result.defangedIOCs = (typeof defangedIOCs !== 'undefined') ? defangedIOCs : 'undefined';
        
        // Check the defanged-list element
        const list = document.getElementById('defanged-list');
        result.listHTML = list ? list.innerHTML.substring(0, 2000) : 'not found';
        result.listText = list ? list.textContent.substring(0, 1000) : 'not found';
        
        // Check submit button handler
        const sendBtn = document.getElementById('send-iocs');
        result.sendBtnExists = !!sendBtn;
        result.sendBtnDisabled = sendBtn ? sendBtn.disabled : 'N/A';
        
        return result;
        """
        
        result = driver.execute_script(inspect_js)
        print("[SELECTED ARRAYS]")
        print(f"  selectedDomains: {result.get('selectedDomains')}")
        print(f"  selectedIPs: {result.get('selectedIPs')}")
        print(f"  selectedURLs: {result.get('selectedURLs')}")
        print(f"  selectedEmails: {result.get('selectedEmails')}")
        print()
        print("[DEFANGED ARRAYS]")
        print(f"  defangedDomains: {result.get('defangedDomains')}")
        print(f"  defangedIPs: {result.get('defangedIPs')}")
        print(f"  defangedURLs: {result.get('defangedURLs')}")
        print(f"  defangedEmails: {result.get('defangedEmails')}")
        print(f"  defangedIOCs: {result.get('defangedIOCs')}")
        print()
        print("[UI ELEMENTS]")
        print(f"  Send button exists: {result.get('sendBtnExists')}")
        print(f"  Send button disabled: {result.get('sendBtnDisabled')}")
        print()
        print("[LIST HTML]")
        print(result.get('listHTML', 'N/A')[:1500])

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_inspect_result.png")

        # Try to find the submit handler
        print("\n" + "=" * 70)
        print("FINDING SUBMIT HANDLER")
        print("=" * 70 + "\n")

        handler_js = """
        const sendBtn = document.getElementById('send-iocs');
        if (!sendBtn) return 'button not found';
        
        // Get all event listeners (this is a hack, may not work)
        const listeners = getEventListeners ? getEventListeners(sendBtn) : 'getEventListeners not available';
        
        // Check onclick attribute
        const onclick = sendBtn.onclick;
        
        // Check for data attributes
        const dataAttrs = {};
        for (let attr of sendBtn.attributes) {
            if (attr.name.startsWith('data-')) {
                dataAttrs[attr.name] = attr.value;
            }
        }
        
        return {
            listeners: listeners,
            onclick: onclick ? onclick.toString().substring(0, 500) : 'null',
            dataAttrs: dataAttrs,
            outerHTML: sendBtn.outerHTML.substring(0, 500)
        };
        """
        
        handler = driver.execute_script(handler_js)
        print(f"Send button outerHTML: {handler.get('outerHTML', 'N/A')}")
        print(f"Data attrs: {handler.get('dataAttrs', 'N/A')}")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
