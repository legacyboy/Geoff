#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: Careful Full Examination
Read all instructions, tabs, and boxes
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def examine():
    print("=" * 70)
    print("SANS HHC 2025 - Terminal 2: Full Examination")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
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

        # Open Terminal 2
        print("[*] Opening Terminal 2...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        objectives = driver.find_elements(By.CSS_SELECTOR, ".badge-item.objective")
        for obj in objectives:
            try:
                title = obj.find_element(By.TAG_NAME, "h2").text
                if "defang" in title.lower():
                    obj.find_element(By.XPATH, ".//button[contains(text(), 'Open Terminal')]").click()
                    print(f"[+] Opened: {title}")
                    break
            except:
                pass
        
        time.sleep(45)
        print("[+] Terminal loaded\n")
        
        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe\n")
        
        time.sleep(10)
        
        # === FULL EXAMINATION ===
        print("=" * 70)
        print("FULL TERMINAL CONTENT")
        print("=" * 70 + "\n")
        
        # Get all text content
        full_text = driver.find_element(By.TAG_NAME, "body").text
        print("[BODY TEXT]:")
        print(full_text)
        print("\n" + "=" * 70 + "\n")
        
        # Find all instructions or help text
        print("[*] Looking for instructions...")
        try:
            instructions = driver.find_elements(By.CSS_SELECTOR, ".instructions, .help-text, .description, p, .info")
            for i, inst in enumerate(instructions[:20]):
                try:
                    text = inst.text.strip()
                    if text and len(text) > 20:
                        print(f"\n  Instruction {i+1}: {text[:200]}")
                except:
                    pass
        except Exception as e:
            print(f"  [!] Error: {e}")
        
        print("\n" + "=" * 70 + "\n")
        
        # Find all tabs
        print("[*] Looking for TABS...")
        tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], button[data-tab], .tab")
        print(f"  Found {len(tabs)} tabs:")
        for i, tab in enumerate(tabs):
            try:
                text = tab.text.strip()
                data_tab = tab.get_attribute("data-tab") or ""
                is_active = "active" in tab.get_attribute("class").lower()
                status = "[ACTIVE]" if is_active else ""
                print(f"    {i+1}. '{text}' (data-tab={data_tab}) {status}")
            except:
                pass
        
        print("\n" + "=" * 70 + "\n")
        
        # Find all input fields
        print("[*] Looking for INPUT FIELDS...")
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"  Found {len(inputs)} input fields:")
        for i, inp in enumerate(inputs):
            try:
                inp_id = inp.get_attribute("id") or ""
                inp_type = inp.get_attribute("type") or "text"
                inp_name = inp.get_attribute("name") or ""
                placeholder = inp.get_attribute("placeholder") or ""
                value = inp.get_attribute("value") or ""
                print(f"    {i+1}. id={inp_id}, type={inp_type}, name={inp_name}")
                print(f"       placeholder={placeholder[:50]}")
                print(f"       value={value[:50]}")
            except:
                pass
        
        print("\n" + "=" * 70 + "\n")
        
        # Find all buttons
        print("[*] Looking for BUTTONS...")
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"  Found {len(buttons)} buttons:")
        for i, btn in enumerate(buttons):
            try:
                text = btn.text.strip()
                btn_id = btn.get_attribute("id") or ""
                btn_type = btn.get_attribute("type") or ""
                if text:
                    print(f"    {i+1}. '{text}' (id={btn_id}, type={btn_type})")
            except:
                pass
        
        print("\n" + "=" * 70 + "\n")
        
        # Look for panels/sections
        print("[*] Looking for PANELS/SECTIONS...")
        panels = driver.find_elements(By.CSS_SELECTOR, ".panel, .section, .card, [class*='panel'], [class*='section']")
        print(f"  Found {len(panels)} panels/sections")
        
        # Look for extracted items/results
        print("\n[*] Looking for EXTRACTED ITEMS...")
        items = driver.find_elements(By.CSS_SELECTOR, ".extracted-item, .ioc-item, .result-item, [class*='extracted'], [class*='ioc']")
        print(f"  Found {len(items)} extracted items/results")
        
        print("\n" + "=" * 70 + "\n")
        
        # Take comprehensive screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_full_examination.png")
        print("[+] Screenshot saved: t2_full_examination.png")
        
        # Switch back to default content for more screenshots
        driver.switch_to.default_content()
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_modal_view.png")
        print("[+] Screenshot saved: t2_modal_view.png")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\n[!] Press Enter to close browser...")
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    examine()
