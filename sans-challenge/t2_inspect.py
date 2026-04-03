#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: INSPECT extraction and defanging
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def inspect():
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: INSPECT")
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
        
        time.sleep(5)
        
        # Extract DOMAINS only
        print("[*] Extracting DOMAINS...")
        driver.find_element(By.XPATH, "//button[@data-ioc-type='domains']").click()
        time.sleep(2)
        
        domain_input = driver.find_element(By.ID, "domain-regex")
        domain_input.clear()
        domain_input.send_keys(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # Check what was extracted
        print("\n[*] Checking extracted domains...")
        html = driver.find_element(By.ID, "selected-domains-list").get_attribute("innerHTML")
        text = driver.find_element(By.ID, "selected-domains-list").text
        count = driver.find_element(By.ID, "domain-count").text
        
        print(f"  Count: {count}")
        print(f"  Text: {text}")
        print(f"  HTML: {html[:500]}")
        
        # Now go to defang tab and check summary
        driver.find_element(By.XPATH, "//button[@data-tab='defang-tab']").click()
        time.sleep(3)
        print("\n[*] On Defang tab")
        
        # Check summary counts
        try:
            summary_html = driver.find_element(By.CLASS_NAME, "selected-summary").get_attribute("innerHTML")
            print(f"\n[*] Summary HTML:\n{summary_html}")
        except:
            print("[!] Could not find summary")
        
        # Check defanged list
        try:
            defanged_html = driver.find_element(By.ID, "defanged-list").get_attribute("innerHTML")
            defanged_text = driver.find_element(By.ID, "defanged-list").text
            print(f"\n[*] Defanged list text: {defanged_text}")
            print(f"[*] Defanged list HTML: {defanged_html[:500]}")
        except:
            print("[!] Could not find defanged list")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_inspect.png")
        print("\n[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    inspect()
