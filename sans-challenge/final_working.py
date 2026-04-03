#!/usr/bin/env python3
"""
SANS HHC 2025 - Final Working Solution
Waits for dynamic challenge UI to load inside iframe
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
    print("=" * 70)
    print("SANS HHC 2025 - Final Working Solution")
    print("=" * 70 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 30)

    try:
        # Step 1: Login
        print("[*] Step 1: Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in")

        # Step 2: Enter game
        print("\n[*] Step 2: Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(15)
        print("[+] In game world")

        # Step 3: Enable CTF Mode
        print("\n[*] Step 3: Enabling CTF Mode...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)

        try:
            ctf = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//*[contains(text(), 'CTF Style')]")))
            ctf.click()
            print("[+] CTF Mode enabled")
            time.sleep(3)
        except:
            print("[!] CTF button issue")

        # Step 4: Open Objectives
        print("\n[*] Step 4: Opening Objectives...")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(10)
        print("[+] Objectives loaded")

        # Step 5: Click terminal button
        print("\n[*] Step 5: Clicking terminal button...")
        try:
            term_btn = wait.until(EC.element_to_be_clickable(
                (By.XPATH, "//button[contains(text(), 'Open Terminal')]")))
            term_btn.click()
            print("[+] Terminal button clicked")
            time.sleep(20)  # Extra time for iframe to load
        except Exception as e:
            print(f"[!] Terminal button error: {e}")

        # Step 6: Switch to iframe and find challenge input
        print("\n[*] Step 6: Finding iframe and challenge input...")

        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"[*] Found {len(iframes)} iframes")

        if not iframes:
            print("[!] No iframe found")
            return

        # Switch to iframe
        driver.switch_to.frame(iframes[0])
        print("[+] Switched to iframe")

        # Wait for terminal to fully load
        print("[*] Waiting for terminal to initialize...")
        time.sleep(15)

        # CRITICAL: The challenge UI loads dynamically - wait for it
        print("\n[*] Looking for challenge input (dynamically loaded)...")

        challenge_input = None

        # Method 1: Wait for any input to appear
        try:
            print("[*] Method 1: Waiting for input elements...")
            WebDriverWait(driver, 20).until(
                EC.presence_of_all_elements_located((By.TAG_NAME, "input"))
            )
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"[+] Found {len(inputs)} inputs")

            for inp in inputs:
                try:
                    inp_type = inp.get_attribute("type")
                    inp_class = inp.get_attribute("class")
                    inp_placeholder = inp.get_attribute("placeholder")

                    # Look for text input (not button)
                    if inp_type == "text":
                        challenge_input = inp
                        print(f"[+] Found text input: class={inp_class}, placeholder={inp_placeholder}")
                        break
                except:
                    pass
        except Exception as e:
            print(f"[!] Method 1 failed: {e}")

        # Method 2: Look for contenteditable divs
        if not challenge_input:
            try:
                print("\n[*] Method 2: Looking for contenteditable divs...")
                editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
                print(f"[*] Found {len(editables)} contenteditables")

                for elem in editables:
                    try:
                        if elem.is_displayed():
                            # Check if it's NOT the xterm shell
                            elem_class = elem.get_attribute("class") or ""
                            if "xterm" not in elem_class:
                                challenge_input = elem
                                print(f"[+] Found challenge editable: class={elem_class}")
                                break
                    except:
                        pass
            except Exception as e:
                print(f"[!] Method 2 failed: {e}")

        # Method 3: JavaScript injection to find challenge elements
        if not challenge_input:
            try:
                print("\n[*] Method 3: Using JavaScript to find challenge elements...")
                script = """
                    var results = [];
                    var all = document.querySelectorAll('input[type="text"], [contenteditable]:not(.xterm-screen)');
                    for (var i = 0; i < all.length; i++) {
                        var el = all[i];
                        if (el.offsetParent !== null) {  // Check if visible
                            results.push({
                                tag: el.tagName,
                                id: el.id,
                                class: el.className,
                                type: el.type,
                                placeholder: el.placeholder
                            });
                        }
                    }
                    return results;
                """
                js_results = driver.execute_script(script)
                print(f"[*] JS found {len(js_results)} potential inputs")

                for elem in js_results:
                    print(f"  [{elem['tag']}] id={elem['id']}, class={elem['class']}, type={elem['type']}")
                    if elem['tag'] == 'INPUT' and elem['type'] == 'text':
                        challenge_input = driver.find_element(By.ID, elem['id']) if elem['id'] else None
                        if not challenge_input and elem['class']:
                            challenge_input = driver.find_element(By.CLASS_NAME, elem['class'].split()[0])
                        break
            except Exception as e:
                print(f"[!] Method 3 failed: {e}")

        # Method 4: Check for React-rendered challenge components
        if not challenge_input:
            try:
                print("\n[*] Method 4: Looking for React challenge components...")
                # Common patterns for challenge inputs
                selectors = [
                    "input[placeholder*='answer' i]",
                    "input[placeholder*='flag' i]",
                    "[data-challenge] input",
                    ".challenge-input",
                    ".answer-input",
                    "#challenge-input",
                    "#answer-input"
                ]

                for selector in selectors:
                    try:
                        elems = driver.find_elements(By.CSS_SELECTOR, selector)
                        for elem in elems:
                            if elem.is_displayed():
                                challenge_input = elem
                                print(f"[+] Found challenge input with selector: {selector}")
                                break
                        if challenge_input:
                            break
                    except:
                        pass
            except Exception as e:
                print(f"[!] Method 4 failed: {e}")

        # Step 7: Solve the challenge
        if challenge_input:
            print("\n" + "=" * 70)
            print("[*] Step 7: SOLVING CHALLENGE")
            print("=" * 70)

            # Click the input
            challenge_input.click()
            time.sleep(2)

            # Clear any existing text
            challenge_input.clear()
            time.sleep(1)

            # Type the answer
            print("[*] Typing 'answer'...")
            challenge_input.send_keys("answer")
            time.sleep(2)

            # Submit
            print("[*] Submitting...")
            challenge_input.send_keys(Keys.RETURN)
            time.sleep(10)

            print("[+] Answer submitted!")

            # Check for success
            body_text = driver.find_element(By.TAG_NAME, "body").text
            success_words = ['congratulations', 'correct', 'completed', 'success', 'badge', 'award', 'solved']
            if any(word in body_text.lower() for word in success_words):
                print("\n" + "=" * 70)
                print("[✓] CHALLENGE SOLVED!")
                print("=" * 70)
            else:
                print("\n[!] Check screenshot for result")

        else:
            print("\n[!] Could not find challenge input with any method")

        # Take final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/final_result.png")
        print("\n[+] Final screenshot saved")

        # Switch back to parent for final state
        driver.switch_to.default_content()

    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\nPress Enter to close browser...")
        driver.quit()
        print("[+] Done")


if __name__ == "__main__":
    solve()
