#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: "It's All About Defang" - FINAL WORKING SOLUTION
Key discovery: The "Apply All Defanging" button is WIP/broken!
Must use SED command input instead.
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
    print("SANS HHC 2025 - Terminal 2: It's All About Defang")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
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
        print("[*] Opening Terminal 2...")
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
        
        time.sleep(5)
        
        # === STEP 1: EXTRACT ALL IOCS ===
        print("=" * 70)
        print("STEP 1: Extract IOCs")
        print("=" * 70 + "\n")
        
        # DOMAINS
        print("[*] Extracting DOMAINS...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='domains']").click()
        time.sleep(2)
        driver.find_element(By.ID, "domain-regex").clear()
        driver.find_element(By.ID, "domain-regex").send_keys(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        print("[+] Domains extracted")
        
        # IPs
        print("[*] Extracting IPs...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='ips']").click()
        time.sleep(2)
        driver.find_element(By.ID, "ip-regex").clear()
        driver.find_element(By.ID, "ip-regex").send_keys(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        driver.find_element(By.ID, "ip-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        print("[+] IPs extracted")
        
        # URLs
        print("[*] Extracting URLs...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='urls']").click()
        time.sleep(2)
        driver.find_element(By.ID, "url-regex").clear()
        driver.find_element(By.ID, "url-regex").send_keys(r"https?://[^\s\"]+")
        driver.find_element(By.ID, "url-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        print("[+] URLs extracted")
        
        # Emails
        print("[*] Extracting Emails...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='emails']").click()
        time.sleep(2)
        driver.find_element(By.ID, "email-regex").clear()
        driver.find_element(By.ID, "email-regex").send_keys(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "email-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        print("[+] Emails extracted")
        
        # === STEP 2: DEFANG USING SED COMMANDS ===
        print("\n" + "=" * 70)
        print("STEP 2: Defang using SED commands")
        print("=" * 70 + "\n")
        
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("[+] On Defang & Report tab")
        
        # The "Apply All Defanging" button is WIP! Use SED input instead.
        print("[*] Looking for SED command input...")
        
        # Find SED input field
        sed_input = driver.find_element(By.ID, "sed-command")
        sed_input.clear()
        
        # SED command to defang domains and IPs (replace . with [.])
        sed_input.send_keys(r's/\./[.]/g')
        print("[+] Entered SED command: s/\\./[.]/g")
        time.sleep(1)
        
        # Click Apply SED
        driver.find_element(By.ID, "apply-sed-btn").click()
        print("[+] Applied SED command")
        time.sleep(3)
        
        # Now defang URLs (replace http with hxxp)
        sed_input.clear()
        sed_input.send_keys(r's/http/hxxp/g')
        print("[+] Entered SED command: s/http/hxxp/g")
        time.sleep(1)
        driver.find_element(By.ID, "apply-sed-btn").click()
        print("[+] Applied SED command")
        time.sleep(3)
        
        # Defang emails (replace @ with [@])
        sed_input.clear()
        sed_input.send_keys(r's/@/[@]/g')
        print("[+] Entered SED command: s/@/[@]/g")
        time.sleep(1)
        driver.find_element(By.ID, "apply-sed-btn").click()
        print("[+] Applied SED command")
        time.sleep(3)
        
        # === STEP 3: SUBMIT REPORT ===
        print("\n" + "=" * 70)
        print("STEP 3: Submit Report")
        print("=" * 70 + "\n")
        
        driver.find_element(By.ID, "submit-report-btn").click()
        print("[+] Clicked Submit Report")
        time.sleep(5)
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_final_result.png")
        print("\n[+] Screenshot saved: t2_final_result.png")
        
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
            print("\n[✓✓✓] CHALLENGE CONFIRMED IN ACHIEVEMENTS!")
            return True
        else:
            print("\n[!] Not in achievements yet")
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
