#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Aggressive Input
Tries multiple input methods repeatedly
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def check_complete(driver):
    """Check if challenge is complete"""
    try:
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(8)
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        return any(k in html.lower() for k in ['completed', 'solved', 'fa-check'])
    except:
        return False


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Aggressive Input")
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

        # Try multiple times
        for attempt in range(1, 6):
            print(f"\n{'='*60}")
            print(f"ATTEMPT {attempt}/5")
            print(f"{'='*60}")

            if check_complete(driver):
                print("\n[✓✓✓] ALREADY COMPLETE!")
                return True

            # Open terminal
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(10)
            driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
            time.sleep(30)

            # Switch to iframe
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            if iframes:
                driver.switch_to.frame(iframes[0])

            time.sleep(10)

            # AGGRESSIVE INPUT - Try multiple methods
            print("\n[*] Method 1: ActionChains to xterm screen...")
            try:
                xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
                actions = ActionChains(driver)
                actions.move_to_element(xterm)
                actions.click()
                actions.send_keys("answer")
                actions.send_keys(Keys.RETURN)
                actions.perform()
                time.sleep(5)
                print("[+] Method 1 done")
            except Exception as e:
                print(f"[!] Method 1 failed: {e}")

            print("\n[*] Method 2: Direct textarea input...")
            try:
                textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
                textarea.click()
                time.sleep(1)
                textarea.send_keys("answer")
                time.sleep(1)
                textarea.send_keys(Keys.RETURN)
                time.sleep(5)
                print("[+] Method 2 done")
            except Exception as e:
                print(f"[!] Method 2 failed: {e}")

            print("\n[*] Method 3: JavaScript injection...")
            try:
                driver.execute_script("""
                    var ta = document.querySelector('.xterm-helper-textarea');
                    if (ta) {
                        ta.value = 'answer';
                        ta.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter', keyCode: 13}));
                        ta.dispatchEvent(new KeyboardEvent('keyup', {key: 'Enter', keyCode: 13}));
                    }
                """)
                time.sleep(5)
                print("[+] Method 3 done")
            except Exception as e:
                print(f"[!] Method 3 failed: {e}")

            # Switch back
            driver.switch_to.default_content()

            # Close modal
            try:
                driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
                time.sleep(3)
            except:
                pass

            # Check completion
            if check_complete(driver):
                print("\n" + "="*60)
                print("[✓✓✓] CHALLENGE COMPLETE!")
                print("="*60)
                return True
            else:
                print("[!] Not complete yet")

        print("\n[!] Max attempts reached")
        return False

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    success = solve()
    exit(0 if success else 1)
