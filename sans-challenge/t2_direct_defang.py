#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Direct defangIOCs() call
Call the defang function directly after setting SED value
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
    print("SANS HHC 2025 - Terminal 2: Direct defangIOCs() Call")
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
        
        # === EXTRACT IOCS via forms ===
        print("=" * 70)
        print("STEP 1: Extract IOCs via forms")
        print("=" * 70 + "\n")
        
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
        
        # === DEFANG by calling defangIOCs() directly ===
        print("=" * 70)
        print("STEP 2: Defang via direct defangIOCs() calls")
        print("=" * 70 + "\n")
        
        # Call defangIOCs() multiple times with different SED commands
        sed_commands = [
            r"s/\./[.]/g",      # dots
            r"s/@/[@]/g",       # @
            r"s/http/hxxp/g",   # http
            r"s/:\/\//[://]/g"  # ://
        ]
        
        for i, sed_cmd in enumerate(sed_commands):
            print(f"[*] Running defangIOCs() with: {sed_cmd}")
            
            # Set SED value and call defangIOCs
            js_code = f"""
            document.getElementById('defang-sed').value = "{sed_cmd}";
            defangIOCs();
            return 'Command {i+1} executed';
            """
            
            result = driver.execute_script(js_code)
            print(f"  [+] {result}")
            time.sleep(3)
        
        # Check defanged list
        defanged_js = """
        const list = document.getElementById('defanged-list');
        return list ? list.innerHTML : 'not found';
        """
        defanged_html = driver.execute_script(defanged_js)
        print(f"\n[*] Defanged list HTML: {defanged_html[:500]}")
        
        # Also check the arrays
        check_js = """
        return {
            defangedIOCs: defangedIOCs.length,
            defangedDomains: defangedDomains.length,
            defangedIPs: defangedIPs.length,
            defangedURLs: defangedURLs.length,
            defangedEmails: defangedEmails.length
        };
        """
        arrays = driver.execute_script(check_js)
        print(f"[*] Defanged arrays: {arrays}")
        
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_direct_result.png")
        
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
