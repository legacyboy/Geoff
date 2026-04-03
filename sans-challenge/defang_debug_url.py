#!/usr/bin/env python3
"""
SANS HHC 2025 - Debug URL extraction
Maybe the issue is not defanging but URL extraction!
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
    print("SANS HHC 2025 - Defang Challenge - Debug URL Extraction")
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

        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)

        print("[*] Enabling CTF mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(8)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(5)
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

        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")

        time.sleep(10)

        # Try extracting with a simpler URL pattern
        print("\n[*] Extracting URLs with different patterns...")
        
        # Test 1: Very broad pattern
        print("\n[Test 1] Broad URL pattern...")
        driver.find_element(By.CSS_SELECTOR, "[data-ioc-type='urls']").click()
        time.sleep(3)
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        time.sleep(1)
        url_input.send_keys(r'https?://[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        
        # Check what was extracted
        check_js = """
        const list = document.getElementById('selected-urls-list');
        return list ? list.textContent : 'not found';
        """
        result = driver.execute_script(check_js)
        print(f"Extracted URLs: {result}\n")
        
        # Take screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/url_extract_debug.png")

        # Test 2: Try extracting specific URLs
        print("[Test 2] Specific URL pattern...")
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        time.sleep(1)
        url_input.send_keys(r'https://icicleinnovations\.mail/[^\s]+')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        
        result = driver.execute_script(check_js)
        print(f"Extracted URLs: {result}\n")
        
        # Test 3: Try with full URL paths
        print("[Test 3] Exact URL pattern...")
        url_input = driver.find_element(By.ID, "url-regex")
        url_input.clear()
        time.sleep(1)
        url_input.send_keys(r'https://icicleinnovations\.mail/(renovation-planner\.exe|upload_photos)')
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "#url-form button[type='submit']").click()
        time.sleep(4)
        
        result = driver.execute_script(check_js)
        print(f"Extracted URLs: {result}\n")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
