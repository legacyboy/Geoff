#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" - Direct Path
Settings → CTF Mode → Objectives → Terminal
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
    print("SANS HHC 2025 - Defang Challenge - Direct Path")
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

        # Step 3: Settings → CTF Mode (AS SPECIFIED BY DAN)
        print("[*] Step 3: Going to Settings → CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(10)
        try:
            ctf_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'CTF Style') or contains(@class, 'ctf')]")
            ctf_btn.click()
            print("[+] CTF Mode activated")
            time.sleep(5)
        except Exception as e:
            print(f"[!] CTF button issue: {e}")
            # Try alternate approach
            try:
                driver.find_element(By.XPATH, "//*[contains(text(), 'CTF')]").click()
                time.sleep(5)
                print("[+] CTF Mode activated (alt)")
            except:
                print("[!] Could not activate CTF mode, continuing anyway")
        print()

        # Step 4: Objectives → Open Terminal (AS SPECIFIED BY DAN)
        print("[*] Step 4: Going to Objectives → Open Terminal...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Find and open the defang terminal
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"[*] Found {len(objectives)} objectives")
        
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                print(f"  - {title}")
                if "defang" in title.lower():
                    btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]")
                    btn.click()
                    print(f"[+] Opened: {title}")
                    break
            except Exception as e:
                pass
        
        time.sleep(50)  # Wait for terminal to load
        print("[+] Terminal loaded\n")

        # Step 5: Switch to iframe
        print("[*] Step 5: Switching to terminal iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")
        
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        else:
            print("[!] No iframe found!")
            return False

        time.sleep(10)

        # Step 6: Extract IOCs
        print("=" * 70)
        print("STEP 6: Extracting IOCs")
        print("=" * 70 + "\n")

        # Get email content to understand what we're working with
        eml_content = driver.execute_script("return document.getElementById('eml-content').textContent;")
        print(f"[*] Email loaded: {len(eml_content)} chars\n")

        # Extract domains
        print("[*] Extracting domains...")
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r'[a-zA-Z0-9-]*\.?icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#domain-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Domains extracted")

        # Extract IPs (attacker IPs only)
        print("[*] Extracting IPs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='ips']").click()
        time.sleep(3)
        ip_input = driver.find_element(By.ID, "ip-regex")
        ip_input.clear()
        ip_input.send_keys(r'172\.[0-9]+\.[0-9]+\.[0-9]+|192\.[0-9]+\.[0-9]+\.[0-9]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#ip-form button[type='submit']").click()
        time.sleep(4)
        print("[+] IPs extracted")

        # Extract URLs
        print("[*] Extracting URLs...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        url_input.send_keys(r'https?://[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        print("[+] URLs extracted")

        # Extract emails
        print("[*] Extracting emails...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='emails']").click()
        time.sleep(3)
        email_input = driver.find_element(By.ID, "email-regex")
        email_input.clear()
        email_input.send_keys(r'[a-zA-Z0-9._%+-]+@icicleinnovations\.mail')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#email-form button[type='submit']").click()
        time.sleep(4)
        print("[+] Emails extracted\n")

        # Step 7: Switch to Defang tab
        print("[*] Step 7: Switching to Defang tab...")
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(10)
        print("[+] On Defang tab\n")

        # Step 8: Click ALL quick defang buttons
        print("=" * 70)
        print("STEP 8: Applying defang transformations")
        print("=" * 70 + "\n")

        buttons = [
            ('defang-all-dots', '. → [.]', 5),
            ('defang-at', '@ → [@]', 5),
            ('defang-http', 'HTTP → HXXP', 5),
            ('defang-protocol', ':// → [://]', 5)
        ]

        for btn_id, desc, delay in buttons:
            try:
                btn = driver.find_element(By.ID, btn_id)
                btn.click()
                print(f"[+] Clicked '{desc}' button")
                time.sleep(delay)
            except Exception as e:
                print(f"[!] Could not click '{desc}': {e}")

        print("[+] All defang buttons clicked\n")

        # Step 9: Verify defanged list
        print("=" * 70)
        print("STEP 9: Verifying defanged list")
        print("=" * 70 + "\n")

        check_js = """
        const list = document.getElementById('defanged-list');
        if (list) {
            const text = list.textContent;
            return {
                hasItems: text.length > 100,
                preview: text.substring(0, 400),
                hasUnescapedDots: text.includes('.') && !text.includes('[.]'),
                hasUnescapedAt: text.includes('@') && !text.includes('[@]'),
                hasUnescapedHttp: (text.includes('http://') || text.includes('https://')) && !text.includes('hxxp')
            };
        }
        return { hasItems: false };
        """

        result = driver.execute_script(check_js)
        print(f"[*] Has items: {result['hasItems']}")
        print(f"[*] Preview: {result['preview']}\n")

        if result.get('hasUnescapedDots'):
            print("[!] WARNING: Still has unescaped dots!")
        if result.get('hasUnescapedAt'):
            print("[!] WARNING: Still has unescaped @!")
        if result.get('hasUnescapedHttp'):
            print("[!] WARNING: Still has unescaped http!")

        # Step 10: Submit
        print("\n[*] Step 10: Submitting...")
        send_btn = driver.find_element(By.ID, "send-iocs")
        send_btn.click()
        print("[+] Clicked 'Send to Security Team'")
        time.sleep(20)

        # Check result
        alert_js = """
        const alert = document.getElementById('alert');
        return alert ? alert.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert: {alert}\n")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_result_final.png")
        print("[+] Screenshot saved\n")

        # Step 11: Verify in achievements
        print("[*] Step 11: Verifying completion...")
        driver.switch_to.default_content()

        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn, button[title='Close']")
            close_btn.click()
            time.sleep(5)
        except:
            pass

        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(20)

        text = driver.find_element(By.TAG_NAME, "body").text

        if "defang" in text.lower() or "all about" in text.lower():
            print("\n" + "=" * 70)
            print("[✓✓✓] CHALLENGE COMPLETE!")
            print("=" * 70)
            return True
        else:
            print("\n[!] Challenge NOT in achievements")
            # Show achievements page text
            print("[*] Achievements page text:")
            print(text[:1000])
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
