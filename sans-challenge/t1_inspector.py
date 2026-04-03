#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 Inspector
Finds all interactive elements in the terminal iframe
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
    print("SANS HHC 2025 - Terminal 1 Inspector")
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

        # Step 6: Switch to iframe
        print("\n[*] Switching to iframe...")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")
        
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        time.sleep(15)

        # Step 7: INSPECT ALL ELEMENTS
        print("\n" + "=" * 60)
        print("INSPECTING ALL INTERACTIVE ELEMENTS")
        print("=" * 60)
        
        # Get page HTML
        html = driver.page_source
        with open("/home/claw/.openclaw/workspace/sans-challenge/t1_page.html", "w") as f:
            f.write(html)
        print(f"[+] HTML saved ({len(html)} chars)")
        
        # All elements
        all_elements = driver.find_elements(By.XPATH, "//*")
        print(f"\n[*] Total elements: {len(all_elements)}")
        
        # Inputs
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"\n[*] Input elements ({len(inputs)}):")
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
                        value: el.value,
                        visible: el.offsetParent !== null,
                        rect: el.getBoundingClientRect()
                    };
                """, inp)
                print(f"  [{i}] type={attrs['type']}, id={attrs['id']}, class={attrs['class'][:50] if attrs['class'] else 'none'}, visible={attrs['visible']}, rect={attrs['rect']}")
            except:
                pass
        
        # Textareas
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"\n[*] Textarea elements ({len(textareas)}):")
        for i, ta in enumerate(textareas):
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        id: el.id,
                        class: el.className,
                        visible: el.offsetParent !== null
                    };
                """, ta)
                print(f"  [{i}] id={attrs['id']}, class={attrs['class'][:50] if attrs['class'] else 'none'}, visible={attrs['visible']}")
            except:
                pass
        
        # Contenteditable
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"\n[*] Contenteditable elements ({len(editables)}):")
        for i, ed in enumerate(editables):
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        id: el.id,
                        class: el.className,
                        visible: el.offsetParent !== null
                    };
                """, ed)
                print(f"  [{i}] id={attrs['id']}, class={attrs['class'][:50] if attrs['class'] else 'none'}, visible={attrs['visible']}")
            except:
                pass
        
        # Divs with click handlers
        clickable_divs = driver.find_elements(By.CSS_SELECTOR, "div[onclick], div[role='button'], div[tabindex]")
        print(f"\n[*] Clickable divs ({len(clickable_divs)}):")
        for i, div in enumerate(clickable_divs[:10]):  # Limit to first 10
            try:
                attrs = driver.execute_script("""
                    var el = arguments[0];
                    return {
                        id: el.id,
                        class: el.className,
                        role: el.getAttribute('role'),
                        tabindex: el.getAttribute('tabindex'),
                        visible: el.offsetParent !== null
                    };
                """, div)
                print(f"  [{i}] id={attrs['id']}, class={attrs['class'][:50] if attrs['class'] else 'none'}, role={attrs['role']}, visible={attrs['visible']}")
            except:
                pass
        
        # Look for text containing "here" or "answer"
        print("\n[*] Looking for text containing 'here' or 'answer':")
        elements_with_text = driver.find_elements(By.XPATH, "//*[contains(text(), 'here') or contains(text(), 'Here') or contains(text(), 'answer') or contains(text(), 'Answer')]")
        for i, el in enumerate(elements_with_text[:10]):
            try:
                text = el.text[:100]
                tag = el.tag_name
                print(f"  [{i}] <{tag}>: {text}")
            except:
                pass
        
        # Take screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_inspect.png")
        print("\n[+] Screenshot saved")
        
        # Print page text
        print("\n[*] Page text:")
        print(driver.find_element(By.TAG_NAME, "body").text[:1000])

    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        
    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
