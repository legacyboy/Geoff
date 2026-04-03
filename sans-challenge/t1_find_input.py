#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Find the actual challenge input
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
    print("SANS HHC 2025 - Terminal 1 - Find Input")
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
        print("[+] Logged in")

        # Enter game
        print("\n[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)

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
        time.sleep(10)
        
        # BEFORE clicking terminal - check page structure
        print("\n[*] BEFORE clicking terminal:")
        html_before = driver.find_element(By.TAG_NAME, "body").get_attribute("outerHTML")
        print(f"  Body HTML length: {len(html_before)}")
        
        # Look for modals or panels
        modals = driver.find_elements(By.CSS_SELECTOR, ".modal, [role='dialog'], .panel, .challenge")
        print(f"  Modals/panels found: {len(modals)}")

        # Click terminal
        print("\n[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(25)  # Wait for everything to load
        
        # AFTER clicking terminal - check page structure
        print("\n[*] AFTER clicking terminal:")
        html_after = driver.find_element(By.TAG_NAME, "body").get_attribute("outerHTML")
        print(f"  Body HTML length: {len(html_after)}")
        
        # Look for modals or panels again
        modals = driver.find_elements(By.CSS_SELECTOR, ".modal, [role='dialog'], .panel, .challenge, .terminal-panel")
        print(f"  Modals/panels found: {len(modals)}")
        
        # Search for specific text patterns
        body_text = driver.find_element(By.TAG_NAME, "body").text
        if "here" in body_text.lower():
            print("  [+] Found 'here' in body text")
            # Find the surrounding context
            idx = body_text.lower().find("here")
            print(f"  Context: ...{body_text[max(0,idx-50):idx+100]}...")
        
        if ">" in body_text:
            print("  [+] Found '>' in body text")
        
        # Look for React components with specific classes
        react_elements = driver.find_elements(By.CSS_SELECTOR, "[class*='challenge'], [class*='terminal'], [class*='input']")
        print(f"\n[*] React/challenge elements: {len(react_elements)}")
        for i, el in enumerate(react_elements[:10]):
            try:
                cls = el.get_attribute("class")
                tag = el.tag_name
                visible = el.is_displayed()
                print(f"  [{i}] <{tag}> class={cls[:60]}, visible={visible}")
            except:
                pass
        
        # Save full HTML
        with open("/home/claw/.openclaw/workspace/sans-challenge/t1_full.html", "w") as f:
            f.write(html_after)
        print("\n[+] Full HTML saved to t1_full.html")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_search.png")
        print("[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()


if __name__ == "__main__":
    solve()
