#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Manual interaction
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Manual Interaction")
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
        print("[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(40)  # Wait longer

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_manual.png")
        print("[+] Screenshot saved")
        
        # Look at the modal's full structure
        print("\n[*] Examining modal structure...")
        
        # Get the modal HTML
        modal_html = driver.find_element(By.CSS_SELECTOR, ".hhc-modal").get_attribute("outerHTML")
        
        # Check if there's any text input outside the iframe
        body = driver.find_element(By.TAG_NAME, "body")
        
        # Look for all elements that might be inputs
        print("\n[*] Looking for all potential input elements...")
        
        # Check for shadow DOM elements
        try:
            shadow_check = driver.execute_script("""
                var allElements = document.querySelectorAll('*');
                var shadowHosts = [];
                for (var i = 0; i < allElements.length; i++) {
                    if (allElements[i].shadowRoot) {
                        shadowHosts.push(allElements[i].tagName + ' ' + allElements[i].className);
                    }
                }
                return shadowHosts;
            """)
            print(f"[*] Shadow hosts found: {shadow_check}")
        except:
            pass
        
        # Try to find if there's a challenge UI that appears
        print("\n[*] Waiting and checking for dynamic content...")
        time.sleep(10)
        
        # Check for any new elements
        html_now = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        print(f"[*] Body HTML length: {len(html_now)}")
        
        if "answer" in html_now.lower():
            print("[+] Found 'answer' in HTML")
        if "here" in html_now.lower():
            print("[+] Found 'here' in HTML")
        
        # Save full HTML
        with open("/home/claw/.openclaw/workspace/sans-challenge/t1_body.html", "w") as f:
            f.write(html_now)
        print("\n[+] Full body HTML saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        time.sleep(5)
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
