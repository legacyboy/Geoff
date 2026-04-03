#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Window Checker
Checks all windows for the challenge input
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
    print("SANS HHC 2025 - Terminal 1 Window Checker")
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

        # Screenshot before clicking
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_pre_click.png")
        print("\n[+] Screenshot saved: t1_pre_click.png")

        # Step 5: Click terminal button and track windows
        print("\n[*] Tracking windows before click...")
        original_windows = driver.window_handles
        print(f"[*] Windows before click: {len(original_windows)}")

        print("\n[*] Clicking terminal button...")
        try:
            term_btn = wait.until(lambda d: d.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]"))
            term_btn.click()
            print("[+] Terminal button clicked")
        except Exception as e:
            print(f"[!] Terminal button error: {e}")

        # Wait for any new window
        time.sleep(15)
        
        all_windows = driver.window_handles
        print(f"\n[*] Windows after click: {len(all_windows)}")
        
        # Check each window
        for i, window in enumerate(all_windows):
            print(f"\n{'='*60}")
            print(f"Window {i+1}/{len(all_windows)}")
            print(f"{'='*60}")
            
            driver.switch_to.window(window)
            time.sleep(2)
            
            print(f"[*] URL: {driver.current_url}")
            print(f"[*] Title: {driver.title}")
            
            # Screenshot
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/sans-challenge/t1_window{i+1}.png")
            print(f"[+] Screenshot: t1_window{i+1}.png")
            
            # Find inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"[*] Inputs found: {len(inputs)}")
            
            for j, inp in enumerate(inputs):
                try:
                    attrs = driver.execute_script("""
                        var el = arguments[0];
                        return {
                            type: el.type,
                            id: el.id,
                            class: el.className,
                            placeholder: el.placeholder,
                            visible: el.offsetParent !== null
                        };
                    """, inp)
                    print(f"  [{j}] type={attrs['type']}, id={attrs['id']}, visible={attrs['visible']}, placeholder='{attrs['placeholder']}'")
                except:
                    pass
            
            # Check for challenge text
            body_text = driver.find_element(By.TAG_NAME, "body").text
            if "here" in body_text.lower() or "answer" in body_text.lower():
                print(f"\n[>] CHALLENGE TEXT FOUND!")
                print(f"[*] Text preview: {body_text[:500]}")

        # Go back to first window (main game)
        driver.switch_to.window(all_windows[0])
        
        # Check if there's an iframe in main window
        print("\n" + "="*60)
        print("CHECKING IFRAMES IN MAIN WINDOW")
        print("="*60)
        
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Iframes in main window: {len(iframes)}")
        
        if iframes:
            for i, iframe in enumerate(iframes):
                print(f"\n[*] Iframe {i+1}:")
                src = iframe.get_attribute("src")
                print(f"  src: {src}")
                
                # Switch to iframe
                driver.switch_to.frame(iframe)
                
                # Check inputs in iframe
                iframe_inputs = driver.find_elements(By.TAG_NAME, "input")
                print(f"  Inputs in iframe: {len(iframe_inputs)}")
                
                for j, inp in enumerate(iframe_inputs):
                    try:
                        attrs = driver.execute_script("""
                            var el = arguments[0];
                            return {
                                type: el.type,
                                visible: el.offsetParent !== null
                            };
                        """, inp)
                        print(f"    [{j}] type={attrs['type']}, visible={attrs['visible']}")
                    except:
                        pass
                
                # Switch back
                driver.switch_to.default_content()

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
