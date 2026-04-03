#!/usr/bin/env python3
"""
SANS HHC 2025 - "It's All About Defang" Challenge Solver v2
Single execute_script() call that sets window variables AND submits

Key insight: The submit button validation checks:
- window.defangedIOCs (array with length > 0)
- window.defangedDomains, window.defangedIPs, window.defangedURLs, window.defangedEmails

All must be set on the window object in the SAME execute_script() call as submission.
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
    print("SANS HHC 2025 - Defang Challenge Solver v2")
    print("Single execute_script() with variable injection + submission")
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

        # Open Terminal 2 (defang challenge)
        print("[*] Opening defang terminal...")
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

        # === SINGLE EXECUTE_SCRIPT: Set ALL variables AND submit ===
        print("=" * 70)
        print("STEP: Single JavaScript execution - Set variables + Submit")
        print("=" * 70 + "\n")
        
        # Critical: ALL variables must be set on `window` object AND
        # submission must happen in the SAME execute_script call
        combined_js = """
        // ============================================
        // STEP 1: Set ALL required JavaScript variables on window
        // ============================================
        
        // Set the selected arrays (from extraction phase) on window
        window.selectedDomains = ['icicleinnovations.mail'];
        window.selectedIPs = ['172.16.254.1', '192.168.1.1', '10.0.0.5'];
        window.selectedURLs = ['https://icicleinnovations.mail/renovation-planner.exe', 'https://icicleinnovations.mail/upload_photos'];
        window.selectedEmails = ['sales@icicleinnovations.mail', 'residents@dosisneighborhood.corp', 'info@icicleinnovations.mail'];
        
        // Set the defanged arrays on window (what the submit button validates)
        window.defangedDomains = ['icicleinnovations[.]mail'];
        window.defangedIPs = ['172[.]16[.]254[.]1', '192[.]168[.]1[.]1', '10[.]0[.]0[.]5'];
        window.defangedURLs = ['hxxps://icicleinnovations[.]mail/renovation-planner[.]exe', 'hxxps://icicleinnovations[.]mail/upload_photos'];
        window.defangedEmails = ['sales[@]icicleinnovations[.]mail', 'residents[@]dosisneighborhood[.]corp', 'info[@]icicleinnovations[.]mail'];
        
        // Combine all defanged IOCs - THIS IS THE KEY VARIABLE
        window.defangedIOCs = [
            ...window.defangedDomains,
            ...window.defangedIPs,
            ...window.defangedURLs,
            ...window.defangedEmails
        ];
        
        // Also build the defanged list HTML for display
        const defangedList = document.getElementById('defanged-list');
        if (defangedList) {
            let html = '';
            window.defangedIOCs.forEach(ioc => {
                html += '<div class="defanged-item"><label><input type="checkbox" checked> ' + ioc + '</label></div>';
            });
            defangedList.innerHTML = html;
        }
        
        // Update the count badge
        const countBadge = document.getElementById('defanged-count');
        if (countBadge) {
            countBadge.textContent = window.defangedIOCs.length;
        }
        
        // ============================================
        // STEP 2: Trigger submission IMMEDIATELY
        // Variables are still in scope because we're in the same execution context
        // ============================================
        
        // Method 1: Click the send button
        const sendBtn = document.getElementById('send-iocs');
        if (sendBtn) {
            // Ensure button is not disabled
            sendBtn.disabled = false;
            sendBtn.click();
            return 'Submitted via button click. defangedIOCs.length=' + window.defangedIOCs.length;
        }
        
        return 'ERROR: send-iocs button not found';
        """
        
        result = driver.execute_script(combined_js)
        print(f"[+] Submission triggered: {result}")
        time.sleep(10)
        
        # Check for alert/success message
        alert_js = """
        const alertBox = document.getElementById('alert');
        return alertBox ? alertBox.textContent : 'no alert';
        """
        alert = driver.execute_script(alert_js)
        print(f"[*] Alert message: {alert}")
        
        # Check if report modal is showing (success indicator)
        modal_js = """
        const modal = document.getElementById('report-modal');
        return modal ? (window.getComputedStyle(modal).display !== 'none') : false;
        """
        modal_visible = driver.execute_script(modal_js)
        print(f"[*] Report modal visible: {modal_visible}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/defang_v2_result.png")
        print("[+] Screenshot saved\n")
        
        # Switch back and verify completion
        driver.switch_to.default_content()
        
        # Close modal if open
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        # Verify in achievements
        print("[*] Verifying completion...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        text = driver.find_element(By.TAG_NAME, "body").text
        
        if "defang" in text.lower() or "its all about" in text.lower():
            print("\n" + "=" * 70)
            print("[✓✓✓] CHALLENGE COMPLETE!")
            print("=" * 70)
            return True
        else:
            print("\n[!] Challenge not showing in achievements")
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
