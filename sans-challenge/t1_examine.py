#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Examine terminal content
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
    print("SANS HHC 2025 - Terminal 1 - Examine")
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

        # Objectives
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
            print("[+] Switched to iframe\n")

        time.sleep(10)

        # Get terminal text content
        print("=" * 60)
        print("TERMINAL CONTENT")
        print("=" * 60)

        # Try to get text from xterm
        try:
            # Get canvas content via JavaScript
            terminal_text = driver.execute_script("""
                // Try to get text from xterm
                var term = window.term;
                if (term && term._core) {
                    var buffer = term._core._bufferService.buffer;
                    var lines = [];
                    for (var i = 0; i < buffer.length; i++) {
                        lines.push(buffer.getLine(i).translateToString());
                    }
                    return lines.join('\\n');
                }
                return "Could not get terminal text";
            """)
            print(terminal_text)
        except Exception as e:
            print(f"[!] Could not get terminal text: {e}")

        # Get all text from body
        print("\n" + "=" * 60)
        print("BODY TEXT")
        print("=" * 60)
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(body_text)

        # Save HTML
        html = driver.page_source
        with open("/home/claw/.openclaw/workspace/sans-challenge/t1_terminal.html", "w") as f:
            f.write(html)
        print("\n[+] HTML saved to t1_terminal.html")

        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_examine.png")
        print("[+] Screenshot saved")

        # Look for specific elements
        print("\n" + "=" * 60)
        print("ELEMENTS")
        print("=" * 60)

        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Inputs: {len(inputs)}")

        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"[*] Textareas: {len(textareas)}")

        for i, ta in enumerate(textareas):
            cls = ta.get_attribute("class")
            print(f"  [{i}] class={cls}")

        # Check for challenge prompt
        if "here" in body_text.lower():
            idx = body_text.lower().find("here")
            print(f"\n[*] Found 'here' at position {idx}")
            print(f"[*] Context: ...{body_text[max(0,idx-30):idx+50]}...")

        if ">" in body_text:
            print("\n[*] Found '>' in body text")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        input("\nPress Enter to close...")
        driver.quit()


if __name__ == "__main__":
    solve()
