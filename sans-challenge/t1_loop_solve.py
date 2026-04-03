#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Loop Until Solved
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def is_complete(driver):
    """Check if challenge is complete"""
    try:
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(8)
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        # Check for completion indicators
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check', 'success']):
            return True
        
        # Check if objective has completion class
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        for obj in objectives:
            classes = obj.get_attribute("class")
            if any(k in classes.lower() for k in ['completed', 'solved', 'done']):
                return True
        
        return False
    except:
        return False


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Loop Until Solved")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Initial login
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
        time.sleep(20)

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Check initial status
        if is_complete(driver):
            print("[✓] Challenge already complete!")
            return

        # Loop attempts
        for attempt in range(1, 6):
            print(f"\n{'='*60}")
            print(f"ATTEMPT {attempt}/5")
            print(f"{'='*60}")

            # Open terminal
            print("[*] Opening terminal...")
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(10)
            driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
            time.sleep(30)

            # Try multiple methods to type "answer"
            
            # Method 1: Try iframe textarea
            print("\n[*] Method 1: Iframe textarea...")
            try:
                iframes = driver.find_elements(By.TAG_NAME, "iframe")
                if iframes:
                    driver.switch_to.frame(iframes[0])
                    textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
                    textarea.click()
                    time.sleep(2)
                    textarea.send_keys("answer")
                    time.sleep(1)
                    textarea.send_keys(Keys.RETURN)
                    time.sleep(5)
                    driver.switch_to.default_content()
                    print("[+] Method 1 executed")
            except Exception as e:
                print(f"[!] Method 1 failed: {e}")
                driver.switch_to.default_content()

            # Method 2: JavaScript injection in iframe
            print("\n[*] Method 2: JavaScript in iframe...")
            try:
                iframes = driver.find_elements(By.TAG_NAME, "iframe")
                if iframes:
                    driver.switch_to.frame(iframes[0])
                    driver.execute_script("""
                        // Try to send input to xterm
                        if (window.term) {
                            window.term.input('answer', true);
                        }
                        // Or try textarea
                        var ta = document.querySelector('.xterm-helper-textarea');
                        if (ta) {
                            ta.value = 'answer';
                            ta.dispatchEvent(new KeyboardEvent('keydown', {key: 'Enter'}));
                        }
                    """)
                    time.sleep(5)
                    driver.switch_to.default_content()
                    print("[+] Method 2 executed")
            except Exception as e:
                print(f"[!] Method 2 failed: {e}")
                driver.switch_to.default_content()

            # Method 3: Look for challenge input in parent modal
            print("\n[*] Method 3: Parent modal inputs...")
            try:
                inputs = driver.find_elements(By.CSS_SELECTOR, ".hhc-modal input[type='text']")
                for inp in inputs:
                    if inp.is_displayed():
                        inp.click()
                        time.sleep(1)
                        inp.send_keys("answer")
                        time.sleep(1)
                        inp.send_keys(Keys.RETURN)
                        time.sleep(5)
                        print("[+] Method 3 executed")
                        break
            except Exception as e:
                print(f"[!] Method 3 failed: {e}")

            # Close modal
            print("\n[*] Closing terminal...")
            try:
                close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
                close_btn.click()
                time.sleep(3)
            except:
                pass

            # Check if complete
            print("\n[*] Checking completion status...")
            if is_complete(driver):
                print("\n" + "="*60)
                print("[✓✓✓] CHALLENGE COMPLETE!")
                print("="*60)
                break
            else:
                print("[!] Not complete yet, trying again...")

        # Final status
        print("\n" + "="*60)
        print("FINAL STATUS")
        print("="*60)
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_final_status.png")
        
        text = driver.find_element(By.TAG_NAME, "body").text
        print(text[:800])

    except Exception as e:
        print(f"[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
