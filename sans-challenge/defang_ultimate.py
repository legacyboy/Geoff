#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - ULTIMATE SOLUTION

KEY FIXES vs previous attempts:
1. SED command for :// MUST be s/:\/\//[://]/g (no backslashes in replacement)
   Previous attempts used [:\/\/] which produced literal backslashes in output
2. Also uses Quick Defang buttons as backup strategy
3. Waits properly for UI state
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"

# Correct SED: Note [://] NOT [:\/\/] in the replacement side
# The replacement side of SED does NOT need escaped forward slashes
SED_COMMAND = r"s/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[://]/g"


def wait_for(driver, by, selector, timeout=15):
    """Wait for element to be present and visible."""
    return WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable((by, selector))
    )


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - It's All About Defang - ULTIMATE SOLUTION")
    print("=" * 70)
    print(f"\nSED command: {SED_COMMAND}\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # ================================================================
        # STEP 0: LOGIN
        # ================================================================
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(6)
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
        except Exception:
            print("[~] CTF mode may already be enabled")

        # ================================================================
        # STEP 1: OPEN TERMINAL
        # ================================================================
        print("[*] Opening defang terminal...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        opened = False
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]")
                    btn.click()
                    print(f"[+] Opened: {title}")
                    opened = True
                    break
            except Exception:
                pass

        if not opened:
            print("[!] Could not find defang terminal button!")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_error.png")
            return False

        print("[*] Waiting for terminal to load (60s)...")
        time.sleep(60)

        # ================================================================
        # STEP 2: SWITCH TO IFRAME
        # ================================================================
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if not iframes:
            print("[!] No iframes found!")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_error.png")
            return False

        driver.switch_to.frame(iframes[0])
        print("[+] Switched to iframe")
        time.sleep(8)

        # ================================================================
        # STEP 3: EXTRACT IOCs - STEP 1 TAB
        # ================================================================
        print("\n" + "=" * 70)
        print("STEP 3: EXTRACT IOCs")
        print("=" * 70)

        # --- DOMAINS ---
        print("[*] Extracting domains (malicious only)...")
        try:
            # Make sure we're on extract tab
            driver.find_element(By.CSS_SELECTOR, "[data-tab='extract-tab']").click()
            time.sleep(2)
        except Exception:
            pass

        # Enter domain regex - ONLY malicious icicleinnovations domains
        domain_input = wait_for(driver, By.ID, "domain-regex")
        domain_input.triple_click = lambda: None  # placeholder
        driver.execute_script("arguments[0].value = '';", domain_input)
        domain_input.click()
        domain_input.send_keys(Keys.CONTROL + "a")
        domain_input.send_keys(Keys.DELETE)
        domain_regex = r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail'
        domain_input.send_keys(domain_regex)
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(5)
        print(f"[+] Domains extracted with pattern: {domain_regex}")

        # --- IPs ---
        print("[*] Extracting IPs (malicious only)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = wait_for(driver, By.ID, "ip-regex")
        driver.execute_script("arguments[0].value = '';", ip_input)
        ip_input.click()
        ip_input.send_keys(Keys.CONTROL + "a")
        ip_input.send_keys(Keys.DELETE)
        # Match IPs from icicleinnovations: 172.16.254.1 and 192.168.1.1
        ip_regex = r'172\.16\.254\.1|192\.168\.1\.1'
        ip_input.send_keys(ip_regex)
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(5)
        print(f"[+] IPs extracted with pattern: {ip_regex}")

        # --- URLs ---
        print("[*] Extracting URLs (malicious only)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = wait_for(driver, By.ID, "url-regex")
        driver.execute_script("arguments[0].value = '';", url_input)
        url_input.click()
        url_input.send_keys(Keys.CONTROL + "a")
        url_input.send_keys(Keys.DELETE)
        url_regex = r'https?://icicleinnovations\.mail/[^\s]+'
        url_input.send_keys(url_regex)
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(5)
        print(f"[+] URLs extracted with pattern: {url_regex}")

        # --- Emails ---
        print("[*] Extracting emails (malicious only)...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = wait_for(driver, By.ID, "email-regex")
        driver.execute_script("arguments[0].value = '';", email_input)
        email_input.click()
        email_input.send_keys(Keys.CONTROL + "a")
        email_input.send_keys(Keys.DELETE)
        email_regex = r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail'
        email_input.send_keys(email_regex)
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(5)
        print(f"[+] Emails extracted with pattern: {email_regex}")

        # ================================================================
        # STEP 4: SWITCH TO DEFANG TAB
        # ================================================================
        print("\n" + "=" * 70)
        print("STEP 4: DEFANG & REPORT TAB")
        print("=" * 70)

        driver.find_element(By.CSS_SELECTOR, "[data-tab='defang-tab']").click()
        time.sleep(5)
        print("[+] On Defang & Report tab")

        # ================================================================
        # STEP 5: ENTER SED COMMAND
        # ================================================================
        print("\n" + "=" * 70)
        print("STEP 5: ENTER SED COMMAND")
        print("=" * 70)

        sed_input = wait_for(driver, By.ID, "defang-sed")
        driver.execute_script("arguments[0].value = '';", sed_input)
        sed_input.click()
        sed_input.send_keys(Keys.CONTROL + "a")
        sed_input.send_keys(Keys.DELETE)
        sed_input.send_keys(SED_COMMAND)
        time.sleep(2)
        print(f"[+] Entered SED: {SED_COMMAND}")

        # Click Apply button
        driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
        time.sleep(5)
        print("[+] Clicked Apply")

        # Check what the defanged list shows
        defanged_html = driver.execute_script(
            "return document.getElementById('defanged-list') ? document.getElementById('defanged-list').innerHTML : 'NOT FOUND'"
        )
        print(f"\n[DEBUG] Defanged list HTML:\n{defanged_html}\n")

        # Check for :// still present (should be [://])
        if '://' in defanged_html and '[://]' not in defanged_html:
            print("[!] WARNING: URLs still have undefanged ://!")
            print("[*] Trying Quick Defang protocol button as fallback...")
            try:
                driver.find_element(By.ID, "defang-protocol").click()
                time.sleep(3)
                defanged_html = driver.execute_script(
                    "return document.getElementById('defanged-list').innerHTML"
                )
                print(f"[DEBUG] After protocol button:\n{defanged_html}\n")
            except Exception as e:
                print(f"[!] Protocol button failed: {e}")

        # Screenshot the defang state
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_before_submit.png")

        # ================================================================
        # STEP 6: SUBMIT
        # ================================================================
        print("\n" + "=" * 70)
        print("STEP 6: SEND TO SECURITY TEAM")
        print("=" * 70)

        send_btn = wait_for(driver, By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(10)

        # Check alert message
        alert_text = driver.execute_script(
            "return document.getElementById('alert') ? document.getElementById('alert').textContent : 'no alert'"
        )
        print(f"\n[*] Alert: {alert_text}")

        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_after_submit.png")

        if "success" in alert_text.lower() or "complet" in alert_text.lower() or "sent" in alert_text.lower():
            print("\n[✓] SUCCESS! Challenge appears complete!")
        elif "missing" in alert_text.lower() or "connection" in alert_text.lower() or "check" in alert_text.lower():
            print("[!] Submission failed with alert. Trying modal-based report...")
            
            # Check if a modal appeared
            modal = driver.execute_script(
                "const m = document.getElementById('report-modal'); return m ? m.innerHTML : 'no modal'"
            )
            if modal and len(modal) > 100:
                print("[*] Modal appeared - may be success")
            
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_modal.png")

        # ================================================================
        # STEP 7: VERIFY COMPLETION
        # ================================================================
        print("\n" + "=" * 70)
        print("STEP 7: VERIFY COMPLETION")
        print("=" * 70)

        driver.switch_to.default_content()
        time.sleep(3)

        # Try to close modal if open
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(2)
        except Exception:
            pass

        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(12)

        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()

        if "defang" in body_text or "its all about" in body_text or "all about defang" in body_text:
            print("\n[✓✓✓] CHALLENGE COMPLETE! 'It's All About Defang' in achievements!")
            return True
        else:
            print("\n[!] Not in achievements yet")
            print("[*] Body preview:", body_text[:500])
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_achievements.png")
            return False

    except Exception as e:
        print(f"\n[!] Unhandled error: {e}")
        import traceback
        traceback.print_exc()
        try:
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_ult_crash.png")
        except Exception:
            pass
        return False

    finally:
        print("\n[+] Done. Closing browser.")
        driver.quit()


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
