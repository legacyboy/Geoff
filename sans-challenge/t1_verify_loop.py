#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Verify and Loop until complete
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
    print("SANS HHC 2025 - Terminal 1 - Verify Loop")
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

        # Check current objective status BEFORE
        print("[*] Checking objective status BEFORE terminal...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        before_text = driver.find_element(By.TAG_NAME, "body").text
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before.png")
        print("[+] Screenshot: t1_before.png")
        
        # Look for completion indicators
        completed_keywords = ['completed', 'done', '✓', 'check', 'solved', 'finished']
        if any(k in before_text.lower() for k in completed_keywords):
            print("[✓] Challenge already completed!")
            return

        # Loop: open terminal, type answer, check, repeat until done
        attempt = 0
        max_attempts = 5
        
        while attempt < max_attempts:
            attempt += 1
            print(f"\n{'='*60}")
            print(f"ATTEMPT {attempt}/{max_attempts}")
            print(f"{'='*60}")
            
            # Refresh objectives page
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(10)
            
            # Click terminal
            print("[*] Clicking terminal...")
            driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
            time.sleep(25)
            
            # Switch to iframe
            iframes = driver.find_elements(By.TAG_NAME, "iframe")
            if iframes:
                driver.switch_to.frame(iframes[0])
                print("[+] Switched to iframe")
            
            time.sleep(10)
            
            # Type answer
            print("[*] Typing 'answer'...")
            textarea = driver.find_element(By.CSS_SELECTOR, ".xterm-helper-textarea")
            textarea.click()
            time.sleep(2)
            textarea.send_keys("answer")
            time.sleep(1)
            textarea.send_keys(Keys.RETURN)
            time.sleep(5)
            print("[+] Submitted")
            
            # Switch back
            driver.switch_to.default_content()
            
            # Close terminal modal
            print("[*] Closing terminal...")
            try:
                close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
                close_btn.click()
                time.sleep(3)
                print("[+] Closed")
            except:
                print("[!] Could not find close button")
            
            # Check objective status AFTER
            print("[*] Checking objective status AFTER...")
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(10)
            
            after_text = driver.find_element(By.TAG_NAME, "body").text
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/sans-challenge/t1_after_{attempt}.png")
            print(f"[+] Screenshot: t1_after_{attempt}.png")
            
            # Check for completion
            if any(k in after_text.lower() for k in completed_keywords):
                print("\n" + "="*60)
                print("[✓✓✓] CHALLENGE COMPLETED!")
                print("="*60)
                break
            elif "2" in after_text:
                print("\n[✓] Challenge 2 indicator found - likely complete")
                break
            else:
                print(f"\n[!] Not complete yet. Retrying...")
                print(f"[*] Page text preview:\n{after_text[:500]}\n")
        
        print(f"\n{'='*60}")
        print("FINAL STATUS")
        print(f"{'='*60}")
        final_text = driver.find_element(By.TAG_NAME, "body").text
        print(final_text[:1000])

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_error.png")
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
