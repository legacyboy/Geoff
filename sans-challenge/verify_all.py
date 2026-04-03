#!/usr/bin/env python3
"""
SANS HHC 2025 - Thorough Verification
Check both objectives and achievements pages
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def check():
    print("=" * 60)
    print("SANS HHC 2025 - Thorough Verification")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
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

        # Check Objectives Page
        print("[*] Checking Objectives page...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        objectives_html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        objectives_text = driver.find_element(By.TAG_NAME, "body").text
        
        print(f"\n[*] Objectives text:\n{objectives_text[:1000]}\n")
        
        # Check each objective
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        print(f"[*] Found {len(objectives)} objective(s):\n")
        
        for i, obj in enumerate(objectives):
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                classes = obj.get_attribute("class")
                html_content = obj.get_attribute("innerHTML")
                
                # Check for completion markers
                has_check_icon = 'fa-check' in html_content.lower()
                has_completed_class = 'completed' in classes.lower()
                has_solved_class = 'solved' in classes.lower()
                
                is_complete = has_check_icon or has_completed_class or has_solved_class
                
                status = "✅ COMPLETE" if is_complete else "⏳ PENDING"
                print(f"  {status}: {title}")
                print(f"      Classes: {classes}")
                print(f"      Has check icon: {has_check_icon}")
                print()
            except Exception as e:
                print(f"  [!] Error: {e}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_status.png")
        
        # Check Achievements Page
        print("\n[*] Checking Achievements page...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(10)
        
        achievements_text = driver.find_element(By.TAG_NAME, "body").text
        achievements_html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        print(f"\n[*] Achievements text:\n{achievements_text}\n")
        
        # Look for specific strings
        print("[*] Checking for specific achievements:")
        checks = [
            ("Holiday Hack Orientation", "orientation"),
            ("It's All About Defang", "defang"),
            ("Lynn Schifano", "lynn"),
            ("Phishing", "phish"),
            ("IOC", "ioc"),
        ]
        
        for name, keyword in checks:
            found = keyword.lower() in achievements_text.lower()
            status = "✅" if found else "❌"
            print(f"  {status} {name}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/achievements_status.png")
        
        # Summary
        print("\n" + "="*60)
        print("SUMMARY")
        print("="*60)
        
        if "defang" in objectives_html.lower():
            if "completed" in objectives_html.lower() or "fa-check" in objectives_html.lower():
                print("✅ Terminal 2 appears complete in objectives")
            else:
                print("⏳ Terminal 2 may not be complete")
        
        if "defang" in achievements_text.lower() or "its all about" in achievements_text.lower():
            print("✅ Terminal 2 found in achievements")
        else:
            print("❌ Terminal 2 NOT found in achievements")
            print("   This suggests it may not be fully complete")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    check()
