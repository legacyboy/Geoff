#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Solver (Parent Window)
The challenge input is OUTSIDE the iframe in the parent window
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.support.ui import WebDriverWait
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 (Parent Window Solver)")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Step 1: Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Enter game
        print("\n[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game world")

        # Step 3: Enable CTF Mode
        print("\n[*] Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            ctf = wait.until(lambda d: d.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]"))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            pass

        # Step 4: Open Objectives
        print("\n[*] Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        # Step 5: Click terminal button
        print("\n[*] Clicking terminal button...")
        try:
            term_btn = wait.until(lambda d: d.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]"))
            term_btn.click()
            print("[+] Terminal button clicked")
            time.sleep(20)
        except Exception as e:
            print(f"[!] Terminal button error: {e}")

        # Step 6: Find challenge input in PARENT window (not iframe)
        print("\n[*] Looking for challenge input in parent window...")
        
        # Screenshot before
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_before_parent.png")
        
        # Get all inputs in parent
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} input elements in parent window")
        
        for i, inp in enumerate(inputs):
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        type: el.type,
                        name: el.name,
                        id: el.id,
                        class: el.className,
                        placeholder: el.placeholder,
                        visible: el.offsetParent !== null
                    };
                """, inp)
                print(f"  [{i}] type={attrs['type']}, id={attrs['id']}, class={attrs['class'][:50] if attrs['class'] else 'none'}, placeholder='{attrs['placeholder']}', visible={attrs['visible']}")
            except:
                pass
        
        # Find visible text inputs
        challenge_input = None
        for inp in inputs:
            try:
                inp_type = inp.get_attribute("type") or "text"
                visible = inp.is_displayed()
                
                if visible and inp_type == "text":
                    challenge_input = inp
                    print(f"\n[+] Found visible text input!")
                    break
            except:
                pass
        
        if challenge_input:
            print("\n[*] Typing 'answer' in challenge input...")
            challenge_input.click()
            time.sleep(1)
            challenge_input.send_keys("answer")
            time.sleep(1)
            
            print("[*] Submitting...")
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(5)
            
            print("[+] Answer submitted!")
            
            # Screenshot after
            time.sleep(5)
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_after_submit.png")
            
            # Check for success
            body_text = driver.find_element(By.TAG_NAME, "body").text
            success = ['congratulations', 'correct', 'completed', 'success', 'badge', '2']
            found = [s for s in success if s in body_text.lower()]
            
            if found:
                print(f"\n[✓] SUCCESS! Indicators: {found}")
            else:
                print(f"\n[!] No clear success yet. Check t1_after_submit.png")
        else:
            print("\n[!] No challenge input found")
            
            # Try looking for contenteditable or other elements
            print("\n[*] Looking for contenteditable elements...")
            editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
            print(f"[*] Found {len(editables)} contenteditable elements")
            for ed in editables:
                try:
                    cls = ed.get_attribute("class") or ""
                    print(f"  class={cls[:50]}")
                except:
                    pass

        # Wait to see result
        print("\n[*] Waiting 10 seconds...")
        time.sleep(10)

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
