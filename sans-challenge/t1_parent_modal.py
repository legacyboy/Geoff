#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Look in parent modal
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
    print("SANS HHC 2025 - Terminal 1 - Parent Modal Check")
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

        # Click terminal
        print("[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(25)

        # Stay in parent context
        print("\n[*] Looking in parent modal (not iframe)...")
        
        # Get the modal content
        modals = driver.find_elements(By.CSS_SELECTOR, ".hhc-modal, .modal-frame")
        print(f"[*] Found {len(modals)} modal elements")
        
        for i, modal in enumerate(modals):
            print(f"\n[*] Modal {i}:")
            html = modal.get_attribute("outerHTML")
            print(f"  HTML length: {len(html)}")
            print(f"  Preview: {html[:500]}")
            
        # Look for any input in the modal
        print("\n[*] Looking for inputs in modal...")
        modal_inputs = driver.find_elements(By.CSS_SELECTOR, ".hhc-modal input, .modal-frame input")
        print(f"[*] Found {len(modal_inputs)} inputs in modal")
        
        for inp in modal_inputs:
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        type: el.type,
                        class: el.className,
                        visible: el.offsetParent !== null
                    };
                """, inp)
                print(f"  type={attrs['type']}, class={attrs['class']}, visible={attrs['visible']}")
            except:
                pass
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_modal.png")
        print("\n[+] Screenshot saved")

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
