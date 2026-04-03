#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - View terminal content
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
    print("SANS HHC 2025 - Terminal 1 - View Content")
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
        time.sleep(30)  # Wait for terminal to fully load
        
        # Screenshot of modal
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_modal_open.png")
        print("[+] Screenshot saved: t1_modal_open.png")
        
        # Try to switch to iframe and get content
        print("\n[*] Examining iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
            
            # Wait for terminal to initialize
            time.sleep(10)
            
            # Try to get text from xterm canvas using JavaScript
            try:
                text = driver.execute_script("""
                    // Try to get text from xterm rows
                    var rows = document.querySelectorAll('.xterm-rows div');
                    var text = '';
                    for (var i = 0; i < rows.length; i++) {
                        text += rows[i].textContent + '\\n';
                    }
                    return text;
                """)
                print("\n[*] Terminal text content:")
                print(text if text else "(empty)")
            except Exception as e:
                print(f"[!] Could not get terminal text: {e}")
            
            # Get HTML
            html = driver.page_source
            with open("/home/claw/.openclaw/workspace/sans-challenge/t1_terminal_src.html", "w") as f:
                f.write(html)
            print("\n[+] Terminal HTML saved")
            
            # Take screenshot from inside iframe
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_iframe_view.png")
            print("[+] Screenshot from iframe saved")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
