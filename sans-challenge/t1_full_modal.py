#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Full modal inspection
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Full Modal Inspection")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(3)
        
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)
        print("[+] In game\n")

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Objectives
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Click terminal
        print("[*] Clicking terminal...")
        term_btn = wait.until(EC.element_to_be_clickable((By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
        term_btn.click()
        print("[+] Terminal opened")
        
        # Wait longer for everything to load
        print("[*] Waiting 45 seconds for terminal to fully load...")
        time.sleep(45)

        # Get full modal HTML (parent context)
        driver.switch_to.default_content()
        
        modal = driver.find_element(By.CSS_SELECTOR, ".hhc-modal")
        modal_html = modal.get_attribute("outerHTML")
        
        print("\n[*] Modal HTML:")
        print(modal_html)
        
        with open("/home/claw/.openclaw/workspace/sans-challenge/t1_modal_full.html", "w") as f:
            f.write(modal_html)
        print("\n[+] Modal HTML saved")
        
        # Look for challenge UI elements in modal
        print("\n[*] Looking for challenge UI elements...")
        
        # Check for any text that mentions challenge
        modal_text = modal.text
        print(f"\n[*] Modal text:\n{modal_text}")
        
        # Look for input elements specifically in the modal
        all_elements = modal.find_elements(By.XPATH, ".//*")
        print(f"\n[*] Total elements in modal: {len(all_elements)}")
        
        for elem in all_elements:
            try:
                tag = elem.tag_name
                if tag in ['input', 'textarea']:
                    inp_type = elem.get_attribute("type") or "text"
                    visible = elem.is_displayed()
                    print(f"  [>] {tag}: type={inp_type}, visible={visible}")
                elif tag == 'div':
                    cls = elem.get_attribute("class") or ""
                    if 'challenge' in cls.lower() or 'input' in cls.lower() or 'terminal' in cls.lower():
                        print(f"  [>] div: class={cls}")
            except:
                pass
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_full_modal.png")
        print("\n[+] Screenshot saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
