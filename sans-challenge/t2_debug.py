#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: DEBUG - Check what's actually happening
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def debug():
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: DEBUG")
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
        
        # === EXTRACT IOCS ===
        print("[*] Extracting IOCs...")
        
        # DOMAINS
        driver.find_element(By.XPATH, "//button[@data-ioc-type='domains']").click()
        time.sleep(2)
        driver.find_element(By.ID, "domain-regex").clear()
        driver.find_element(By.ID, "domain-regex").send_keys(r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "domain-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # IPs
        driver.find_element(By.XPATH, "//button[@data-ioc-type='ips']").click()
        time.sleep(2)
        driver.find_element(By.ID, "ip-regex").clear()
        driver.find_element(By.ID, "ip-regex").send_keys(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
        driver.find_element(By.ID, "ip-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # URLs
        driver.find_element(By.XPATH, "//button[@data-ioc-type='urls']").click()
        time.sleep(2)
        driver.find_element(By.ID, "url-regex").clear()
        driver.find_element(By.ID, "url-regex").send_keys(r"https?://[^\s\"]+")
        driver.find_element(By.ID, "url-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        # Emails
        driver.find_element(By.XPATH, "//button[@data-ioc-type='emails']").click()
        time.sleep(2)
        driver.find_element(By.ID, "email-regex").clear()
        driver.find_element(By.ID, "email-regex").send_keys(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        driver.find_element(By.ID, "email-form").find_element(By.TAG_NAME, "button").click()
        time.sleep(3)
        
        print("[+] Extraction complete\n")
        
        # === CHECK WHAT WAS EXTRACTED ===
        print("=" * 70)
        print("CHECKING EXTRACTION RESULTS")
        print("=" * 70 + "\n")
        
        # Check counts
        try:
            domain_count = driver.find_element(By.ID, "domain-count").text
            print(f"[*] Domain count: {domain_count}")
        except:
            print("[!] Could not find domain-count")
        
        try:
            ip_count = driver.find_element(By.ID, "ip-count").text
            print(f"[*] IP count: {ip_count}")
        except:
            print("[!] Could not find ip-count")
            
        try:
            url_count = driver.find_element(By.ID, "url-count").text
            print(f"[*] URL count: {url_count}")
        except:
            print("[!] Could not find url-count")
            
        try:
            email_count = driver.find_element(By.ID, "email-count").text
            print(f"[*] Email count: {email_count}")
        except:
            print("[!] Could not find email-count")
        
        # Check lists
        print("\n[*] Checking extracted lists:")
        try:
            domain_list = driver.find_element(By.ID, "selected-domains-list").text
            print(f"  Domains: {domain_list[:200]}")
        except Exception as e:
            print(f"  [!] Domain list error: {e}")
            
        try:
            ip_list = driver.find_element(By.ID, "selected-ips-list").text
            print(f"  IPs: {ip_list[:200]}")
        except Exception as e:
            print(f"  [!] IP list error: {e}")
            
        try:
            url_list = driver.find_element(By.ID, "selected-urls-list").text
            print(f"  URLs: {url_list[:200]}")
        except Exception as e:
            print(f"  [!] URL list error: {e}")
            
        try:
            email_list = driver.find_element(By.ID, "selected-emails-list").text
            print(f"  Emails: {email_list[:200]}")
        except Exception as e:
            print(f"  [!] Email list error: {e}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_debug.png")
        print("\n[+] Screenshot saved: t2_debug.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\n[!] Press Enter to close...")
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    debug()
