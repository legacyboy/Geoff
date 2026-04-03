#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2 Retry with Careful Observation
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 2 Retry")
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
        print("[+] Terminal loaded")
        
        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(15)
        
        # Get full page content
        print("\n[*] Getting terminal content...")
        html = driver.page_source
        text = driver.find_element(By.TAG_NAME, "body").text
        
        print(f"\n[*] Terminal body text:\n{text[:1500]}\n")
        
        # Look for all buttons and inputs
        print("[*] Finding all interactive elements...")
        
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"\n[*] Found {len(buttons)} buttons:")
        for btn in buttons:
            try:
                txt = btn.text
                btn_id = btn.get_attribute("id") or ""
                btn_class = btn.get_attribute("class") or ""
                print(f"  - '{txt}' (id={btn_id}, class={btn_class[:50]})")
            except:
                pass
        
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"\n[*] Found {len(inputs)} inputs:")
        for inp in inputs:
            try:
                inp_id = inp.get_attribute("id") or ""
                inp_type = inp.get_attribute("type") or "text"
                inp_placeholder = inp.get_attribute("placeholder") or ""
                print(f"  - id={inp_id}, type={inp_type}, placeholder={inp_placeholder}")
            except:
                pass
        
        # Look for tabs
        print("\n[*] Looking for tabs...")
        tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, [data-tab]")
        for tab in tabs:
            try:
                txt = tab.text
                data_tab = tab.get_attribute("data-tab") or ""
                print(f"  - '{txt}' (data-tab={data_tab})")
            except:
                pass
        
        # Screenshot before actions
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_initial.png")
        print("\n[+] Initial screenshot saved: t2_initial.png")
        
        # Check the current state
        print("\n[*] Current tab/section...")
        active_tabs = driver.find_elements(By.CSS_SELECTOR, ".active, .selected, [aria-selected='true']")
        for tab in active_tabs:
            try:
                print(f"  Active: {tab.text}")
            except:
                pass

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
