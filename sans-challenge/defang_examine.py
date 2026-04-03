#!/usr/bin/env python3
"""
SANS HHC 2025 - Examine what's in the challenge text
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os
import json

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 70)
    print("SANS HHC 2025 - Defang Challenge - Examine Challenge Text")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login and navigate
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
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
        print("[+] Terminal loaded")

        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")

        time.sleep(10)

        # Get the full challenge text
        print("\n" + "=" * 70)
        print("EXAMINING CHALLENGE TEXT")
        print("=" * 70 + "\n")

        page_html = driver.execute_script("return document.documentElement.innerHTML;")
        page_text = driver.execute_script("return document.body.innerText;")

        print("[*] Page text:\n")
        print(page_text)
        print("\n" + "=" * 70)

        # Look for specific patterns
        import re

        # Find all URLs
        url_pattern = r'https?://[^\s"]+'
        urls = re.findall(url_pattern, page_text)
        print(f"\n[*] Found {len(urls)} URLs:")
        for url in urls:
            print(f"  - {url}")

        # Find all domains
        domain_pattern = r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        domains = re.findall(domain_pattern, page_text)
        print(f"\n[*] Found {len(domains)} domains (raw):")
        for d in set(domains):
            print(f"  - {d}")

        # Find IPs
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, page_text)
        print(f"\n[*] Found {len(ips)} IPs:")
        for ip in ips:
            print(f"  - {ip}")

        # Find emails
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, page_text)
        print(f"\n[*] Found {len(emails)} emails:")
        for email in emails:
            print(f"  - {email}")

        # Save to file
        with open('/home/claw/.openclaw/workspace/sans-challenge/challenge_content.json', 'w') as f:
            json.dump({
                'urls': urls,
                'domains': list(set(domains)),
                'ips': ips,
                'emails': emails,
                'text': page_text[:2000]
            }, f, indent=2)
        print("\n[+] Saved to challenge_content.json")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/challenge_examine.png")

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
