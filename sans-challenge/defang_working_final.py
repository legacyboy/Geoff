#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - WORKING FINAL

KEY INSIGHTS from main.js analysis:
1. Variables defangedIOCs, defangedDomains etc are module-level 'let' vars
   They ARE accessible from the page context but Selenium executes in a different
   scope - we use them indirectly by triggering the actual UI events.
2. The SED for :// must be: s/:\/\//[://]/g (with [://] NOT [:\/\/] in replacement)
3. The JS has SPECIAL HANDLING: if cmd includes "://" AND "[://]", it applies
   url.replace(/:\/\/g, "[://]") directly - bypassing normal parsing.
4. For multi-command SED: each ; separated command is checked individually.
5. Quick Defang buttons also work - they set the SED value and call defangIOCs().
6. Best approach: Use Quick Defang buttons in sequence (4 clicks) - guaranteed correct.

STRATEGY: Use Quick Defang buttons since they're guaranteed to produce correct output.
Each button sets the SED value and calls defangIOCs() which accumulates transformations.
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


def clear_and_type(driver, element, text):
    """Clear an input field and type new text."""
    driver.execute_script("arguments[0].value = '';", element)
    element.click()
    time.sleep(0.3)
    element.send_keys(Keys.CONTROL + "a")
    element.send_keys(Keys.DELETE)
    time.sleep(0.3)
    element.send_keys(text)


def wait_click(driver, by, selector, timeout=15):
    """Wait for element and click it."""
    el = WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable((by, selector))
    )
    el.click()
    return el


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - It's All About Defang - WORKING FINAL")
    print("=" * 70)

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # ============================================================
        # LOGIN
        # ============================================================
        print("\n[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(6)
        print("[+] Logged in")

        # Click Play Now
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game")

        # Enable CTF mode
        print("[*] Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(8)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(5)
            print("[+] CTF mode enabled")
        except Exception:
            print("[~] CTF already enabled or not found")

        # ============================================================
        # OPEN TERMINAL
        # ============================================================
        print("\n[*] Opening defang terminal...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        opened = False
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]")
                    driver.execute_script("arguments[0].scrollIntoView(true);", btn)
                    time.sleep(0.5)
                    btn.click()
                    print(f"[+] Opened: {title}")
                    opened = True
                    break
            except Exception:
                pass

        if not opened:
            print("[!] Terminal button not found - trying direct URL click")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_notfound.png")
            return False

        print("[*] Waiting 65s for terminal to load...")
        time.sleep(65)
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_loaded.png")

        # ============================================================
        # SWITCH TO IFRAME
        # ============================================================
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframe(s)")
        if not iframes:
            print("[!] No iframes found!")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_noframe.png")
            return False

        driver.switch_to.frame(iframes[0])
        print("[+] Switched to iframe")
        time.sleep(8)

        # Verify we're in the right app
        page_title = driver.execute_script("return document.title;")
        print(f"[*] Page title: {page_title}")

        # ============================================================
        # STEP 1: EXTRACT DOMAINS
        # ============================================================
        print("\n[*] Extracting domains...")
        try:
            # Make sure extract tab is active
            driver.find_element(By.CSS_SELECTOR, "[data-tab='extract-tab']").click()
            time.sleep(2)
        except Exception:
            pass

        # Domain regex - only malicious icicleinnovations domains
        domain_input = WebDriverWait(driver, 15).until(
            EC.presence_of_element_located((By.ID, "domain-regex"))
        )
        # Use JS to set value to avoid issues with special chars
        domain_regex = r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail'
        driver.execute_script(f"document.getElementById('domain-regex').value = '{domain_regex}';")
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(5)

        # Verify
        domain_count = driver.execute_script(
            "return document.getElementById('domain-count') ? document.getElementById('domain-count').textContent : '?'"
        )
        print(f"[+] Domains extracted: {domain_count}")

        # ============================================================
        # STEP 2: EXTRACT IPs
        # ============================================================
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)

        # IP regex - only malicious IPs (172.16.254.1 and 192.168.1.1)
        ip_regex = r'172\.16\.254\.1|192\.168\.1\.1'
        driver.execute_script(f"document.getElementById('ip-regex').value = '{ip_regex}';")
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(5)

        ip_count = driver.execute_script(
            "return document.getElementById('ip-count') ? document.getElementById('ip-count').textContent : '?'"
        )
        print(f"[+] IPs extracted: {ip_count}")

        # ============================================================
        # STEP 3: EXTRACT URLs
        # ============================================================
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)

        # URL regex - only malicious icicleinnovations URLs
        url_regex = r'https?://icicleinnovations\.mail/[^\s]+'
        driver.execute_script(f"document.getElementById('url-regex').value = `{url_regex}`;")
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(5)

        url_count = driver.execute_script(
            "return document.getElementById('url-count') ? document.getElementById('url-count').textContent : '?'"
        )
        print(f"[+] URLs extracted: {url_count}")

        # ============================================================
        # STEP 4: EXTRACT EMAILS
        # ============================================================
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)

        # Email regex - only malicious icicleinnovations emails
        email_regex = r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail'
        driver.execute_script(f"document.getElementById('email-regex').value = '{email_regex}';")
        time.sleep(1)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(5)

        email_count = driver.execute_script(
            "return document.getElementById('email-count') ? document.getElementById('email-count').textContent : '?'"
        )
        print(f"[+] Emails extracted: {email_count}")

        # Check what was selected
        selected_state = driver.execute_script("""
            return {
                domains: typeof selectedDomains !== 'undefined' ? selectedDomains : 'UNDEFINED',
                ips: typeof selectedIPs !== 'undefined' ? selectedIPs : 'UNDEFINED',
                urls: typeof selectedURLs !== 'undefined' ? selectedURLs : 'UNDEFINED',
                emails: typeof selectedEmails !== 'undefined' ? selectedEmails : 'UNDEFINED'
            };
        """)
        print(f"\n[DEBUG] Selected IOCs: {selected_state}")

        # ============================================================
        # STEP 5: SWITCH TO DEFANG TAB
        # ============================================================
        print("\n[*] Switching to Defang & Report tab...")
        driver.find_element(By.CSS_SELECTOR, "[data-tab='defang-tab']").click()
        time.sleep(5)
        print("[+] On Defang & Report tab")

        # ============================================================
        # STEP 6: APPLY DEFANGING VIA QUICK BUTTONS
        # 
        # The Quick Defang buttons each set the SED input and call defangIOCs()
        # They accumulate transformations on the already-defanged array.
        # Order matters: do . first, then @, then http, then ://
        # ============================================================
        print("\n[*] Applying defanging via Quick Defang buttons...")

        # Button 1: . -> [.]
        print("[*] Clicking 'dots' defang button...")
        driver.find_element(By.ID, "defang-all-dots").click()
        time.sleep(3)

        # Button 2: @ -> [@]
        print("[*] Clicking '@' defang button...")
        driver.find_element(By.ID, "defang-at").click()
        time.sleep(3)

        # Button 3: http -> hxxp
        print("[*] Clicking 'http' defang button...")
        driver.find_element(By.ID, "defang-http").click()
        time.sleep(3)

        # Button 4: :// -> [://]
        print("[*] Clicking 'protocol' defang button...")
        driver.find_element(By.ID, "defang-protocol").click()
        time.sleep(3)

        # Check what we have now
        defanged_state = driver.execute_script("""
            return {
                iocs: typeof defangedIOCs !== 'undefined' ? defangedIOCs : 'UNDEFINED',
                domains: typeof defangedDomains !== 'undefined' ? defangedDomains : 'UNDEFINED',
                ips: typeof defangedIPs !== 'undefined' ? defangedIPs : 'UNDEFINED',
                urls: typeof defangedURLs !== 'undefined' ? defangedURLs : 'UNDEFINED',
                emails: typeof defangedEmails !== 'undefined' ? defangedEmails : 'UNDEFINED'
            };
        """)
        print(f"\n[DEBUG] Defanged IOCs state: {defanged_state}")

        # Check defanged count
        defanged_count = driver.execute_script(
            "return document.getElementById('defanged-count') ? document.getElementById('defanged-count').textContent : '?'"
        )
        print(f"\n[*] Defanged count badge: {defanged_count}")

        # Check the HTML list
        defanged_html = driver.execute_script(
            "return document.getElementById('defanged-list') ? document.getElementById('defanged-list').innerHTML : 'NOT FOUND'"
        )
        print(f"\n[DEBUG] Defanged list HTML:\n{defanged_html}\n")

        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_before_submit.png")

        # Validate defanging is correct
        if defanged_state.get('iocs') == 'UNDEFINED' or defanged_state.get('iocs') == []:
            print("[!] WARNING: defangedIOCs is empty or undefined!")
            print("[*] Attempting alternative: single combined SED command...")
            
            # Try single SED with all 4 operations
            # The special :// handling kicks in for cmd containing ":// " and "[://]"
            combined_sed = r"s/\./[.]/g; s/@/[@]/g; s/http/hxxp/g; s/:\/\//[://]/g"
            driver.execute_script(f"""
                document.getElementById('defang-sed').value = String.raw`{combined_sed}`;
            """)
            time.sleep(1)
            driver.find_element(By.CSS_SELECTOR, "#defang-form button[type='submit']").click()
            time.sleep(5)

            defanged_state = driver.execute_script("""
                return {
                    iocs: typeof defangedIOCs !== 'undefined' ? defangedIOCs : 'UNDEFINED',
                    count: typeof defangedIOCs !== 'undefined' ? defangedIOCs.length : -1
                };
            """)
            print(f"[DEBUG] After combined SED: {defanged_state}")

        # Check URLs look correct (should have [://] not backslashes)
        urls_good = False
        if defanged_state.get('urls') and isinstance(defanged_state['urls'], list):
            for url in defanged_state['urls']:
                if '[://]' in url:
                    urls_good = True
                    print(f"[+] URL correctly defanged: {url}")
                elif '://' in url:
                    print(f"[!] URL still has undefanged ://: {url}")
        
        # ============================================================
        # STEP 7: SUBMIT
        # ============================================================
        print("\n" + "=" * 70)
        print("STEP 7: SEND TO SECURITY TEAM")
        print("=" * 70)

        send_btn = WebDriverWait(driver, 15).until(
            EC.element_to_be_clickable((By.ID, "send-iocs"))
        )
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(10)

        # Check alert message
        alert_text = driver.execute_script(
            "return document.getElementById('alert') ? document.getElementById('alert').textContent : 'no alert'"
        )
        print(f"\n[*] Alert message: {alert_text}")

        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_after_submit.png")

        # Check for modal
        modal_visible = driver.execute_script("""
            const m = document.getElementById('report-modal');
            if (!m) return 'no modal';
            return window.getComputedStyle(m).display;
        """)
        print(f"[*] Modal display: {modal_visible}")

        # Determine success
        if "success" in alert_text.lower() or "chi team" in alert_text.lower() or modal_visible not in ('none', 'no modal'):
            print("\n[✓✓✓] SUCCESS INDICATORS FOUND!")
            success = True
        elif "missing" in alert_text.lower() or "connection" in alert_text.lower():
            print(f"\n[!] Submission failed. Error: {alert_text[:200]}")
            success = False
        else:
            print(f"\n[?] Ambiguous result")
            success = False

        # ============================================================
        # STEP 8: VERIFY VIA ACHIEVEMENTS
        # ============================================================
        driver.switch_to.default_content()
        time.sleep(2)

        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(2)
        except Exception:
            pass

        print("\n[*] Checking achievements...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(12)

        body_text = driver.find_element(By.TAG_NAME, "body").text.lower()
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_achievements.png")

        if "defang" in body_text or "its all about" in body_text or "all about defang" in body_text:
            print("\n[✓✓✓] CHALLENGE CONFIRMED COMPLETE IN ACHIEVEMENTS!")
            return True
        else:
            print("\n[!] Not found in achievements page")
            print(f"[*] Body preview: {body_text[:300]}")
            return success

    except Exception as e:
        print(f"\n[!] Unhandled error: {e}")
        import traceback
        traceback.print_exc()
        try:
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_wf_crash.png")
        except Exception:
            pass
        return False

    finally:
        print("\n[+] Closing browser.")
        driver.quit()


if __name__ == "__main__":
    success = solve()
    print(f"\nResult: {'SUCCESS' if success else 'FAILED'}")
    exit(0 if success else 1)
