#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Simple JavaScript input
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
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Simple JS Input")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
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

        # Objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Click terminal
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(35)

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(10)
        
        # Try accessing terminal object
        print("\n[*] Checking for terminal object...")
        result = driver.execute_script("""
            var results = [];
            if (typeof term !== 'undefined') {
                results.push("term exists");
                if (term._core) results.push("has _core");
                if (term.socket) results.push("has socket");
            }
            return results.join(", ");
        """)
        print(f"[*] Terminal check: {result}")
        
        # Click on terminal to focus
        print("\n[*] Focusing terminal...")
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        xterm.click()
        time.sleep(3)
        
        # Send keys character by character with delay
        print("\n[*] Sending 'answer' slowly...")
        textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
        
        chars = ['a', 'n', 's', 'w', 'e', 'r']
        for char in chars:
            textarea.send_keys(char)
            time.sleep(0.3)
        
        time.sleep(1)
        textarea.send_keys(Keys.RETURN)
        time.sleep(5)
        
        print("[+] Sent 'answer'")
        
        # Try JavaScript after
        print("\n[*] Trying JavaScript fallback...")
        driver.execute_script("""
            if (typeof term !== 'undefined' && term._core) {
                // Try to insert text
                term._core._inputHandler.parse("answer");
            }
        """)
        time.sleep(2)
        
        # Try Enter via JS
        driver.execute_script("""
            if (typeof term !== 'undefined' && term._core) {
                term._core._inputHandler.parse(String.fromCharCode(13));
            }
        """)
        time.sleep(5)
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_simple_result.png")
        
        # Verify
        driver.switch_to.default_content()
        
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(3)
        except:
            pass
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
        else:
            print("\n[!] Not complete")
            print(f"Classes: {driver.find_element(By.CSS_SELECTOR, '.badge-item.objective').get_attribute('class')}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
