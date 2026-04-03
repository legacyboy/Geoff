#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Type and verify visible output
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


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - Type and Verify")
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
        time.sleep(20)

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
        time.sleep(15)

        # Click terminal
        print("[*] Opening terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(35)

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] In iframe")
        
        time.sleep(10)
        
        # Screenshot before typing
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before_type.png")
        print("[+] Screenshot before: t1_before_type.png")
        
        # Click on the xterm area to focus it
        print("\n[*] Focusing terminal...")
        xterm = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
        xterm.click()
        time.sleep(3)
        
        # Try typing simple test first
        print("[*] Typing 'answer'...")
        
        # Method: Send keys directly to body with focus
        actions = ActionChains(driver)
        actions.send_keys("answer")
        actions.perform()
        time.sleep(2)
        
        # Screenshot after typing
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_answer.png")
        print("[+] Screenshot after answer: t1_after_answer.png")
        
        # Press Enter
        print("[*] Pressing Enter...")
        actions = ActionChains(driver)
        actions.send_keys(Keys.RETURN)
        actions.perform()
        time.sleep(5)
        
        # Screenshot after submit
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_submit.png")
        print("[+] Screenshot after submit: t1_after_submit.png")
        
        # Try to get canvas screenshot
        print("\n[*] Trying JavaScript screenshot...")
        try:
            driver.execute_script("""
                // Try to capture canvas
                var canvas = document.querySelector('.xterm-text-layer');
                if (canvas) {
                    var dataUrl = canvas.toDataURL('image/png');
                    return dataUrl;
                }
                return null;
            """)
        except:
            pass
        
        # Switch back and verify
        driver.switch_to.default_content()
        print("\n[*] Verifying...")
        
        # Close modal
        try:
            close_btn = driver.find_element(By.CSS_SELECTOR, ".close-modal-btn")
            close_btn.click()
            time.sleep(3)
        except:
            pass
        
        # Check objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_verify.png")
        print("[+] Final screenshot: t1_verify.png")
        
        # Check status
        text = driver.find_element(By.TAG_NAME, "body").text
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        if any(k in html.lower() for k in ['completed', 'solved', 'fa-check']):
            print("\n[✓] CHALLENGE COMPLETE!")
        else:
            print("\n[!] Challenge not complete")
            print(f"[*] Status: objective has classes {driver.find_element(By.CSS_SELECTOR, '.badge-item.objective').get_attribute('class')}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
