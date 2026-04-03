#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: It's All About Defang
Likely requires defanging URLs/IOCs
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


def defang_url(url):
    """Defang a URL by replacing :// with [.] and . with [.]"""
    return url.replace('://', '[://]').replace('.', '[.]')


def defang_email(email):
    """Defang an email by replacing @ with [@] and . with [.]"""
    return email.replace('@', '[@]').replace('.', '[.]')


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 2: It's All About Defang")
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

        # Objectives
        print("[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Find Terminal 2 button
        print("[*] Finding Terminal 2 button...")
        
        # Look for "Its All About Defang" objective
        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        term2_btn = None
        
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    # Found it, click its terminal button
                    term2_btn = obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]")
                    print(f"[+] Found: {title}")
                    break
            except:
                pass
        
        if not term2_btn:
            # Fallback
            term2_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal') and contains(text(), 'Defang')]")
        
        # Click to open
        print("[*] Opening Terminal 2...")
        term2_btn.click()
        time.sleep(40)
        print("[+] Terminal opened")
        
        # Screenshot to see challenge
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_challenge.png")
        print("[+] Screenshot saved")
        
        # Look for challenge content in parent modal
        print("\n[*] Looking for challenge input...")
        
        # Get modal content
        modal_text = driver.find_element(By.CSS_SELECTOR, ".modal-frame").text
        print(f"\n[*] Modal text:\n{modal_text[:800]}\n")
        
        # Look for challenge input (likely same as Terminal 1 - above iframe)
        inputs = []
        for elem in driver.find_elements(By.TAG_NAME, "input"):
            try:
                if elem.is_displayed() and elem.location['y'] < 400:
                    inputs.append(elem)
            except:
                pass
        
        for elem in driver.find_elements(By.TAG_NAME, "textarea"):
            try:
                if elem.is_displayed() and elem.location['y'] < 400:
                    inputs.append(elem)
            except:
                pass
        
        for elem in driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']"):
            try:
                if elem.is_displayed() and elem.location['y'] < 400:
                    inputs.append(elem)
            except:
                pass
        
        if inputs:
            print(f"[+] Found {len(inputs)} challenge input(s)")
            
            # Look at what the challenge wants
            if "defang" in modal_text.lower():
                print("[*] Challenge is about defanging URLs/IOCs")
                
                # Extract any URLs or emails from the challenge text
                import re
                urls = re.findall(r'https?://[^\s\n]+', modal_text)
                emails = re.findall(r'[\w.-]+@[\w.-]+\.[\w]+', modal_text)
                
                print(f"[*] Found URLs: {urls}")
                print(f"[*] Found emails: {emails}")
                
                # For now, try typing "answer" like Terminal 1
                # Terminal 2 might have different requirements
                print("\n[*] Attempting to type 'answer' first...")
                challenge_input = inputs[0]
                challenge_input.click()
                time.sleep(2)
                challenge_input.send_keys("answer")
                time.sleep(1)
                challenge_input.send_keys(Keys.RETURN)
                time.sleep(5)
                print("[+] Submitted 'answer'")
        else:
            print("[!] No challenge inputs found")
            # Try clicking in upper modal area like Terminal 1
            print("[*] Trying click in upper modal...")
            modal = driver.find_element(By.CSS_SELECTOR, ".modal-frame")
            loc = modal.location
            actions = ActionChains(driver)
            actions.move_by_offset(loc['x'] + 200, loc['y'] + 100)
            actions.click()
            actions.send_keys("answer")
            actions.send_keys(Keys.RETURN)
            actions.perform()
            time.sleep(5)
            print("[+] Attempted input")

        # Close modal
        try:
            driver.find_element(By.CSS_SELECTOR, ".close-modal-btn").click()
            time.sleep(3)
        except:
            pass

        # Verify
        print("\n[*] Verifying completion...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        
        html = driver.find_element(By.TAG_NAME, "body").get_attribute("innerHTML")
        
        # Look for completion indicators
        if "completed" in html.lower() or "fa-check" in html.lower():
            print("\n[✓] Challenge completed!")
        else:
            print("\n[!] Not complete - need to analyze challenge requirements")
            print(f"[*] Screenshot saved for analysis: t2_challenge.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
