#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 2: It's All About Defang - Real Terminal Content
Need to read webpage in terminal, do regex, multiple tabs
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
    print("SANS HHC 2025 - Terminal 2: Real Terminal Content")
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
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Find and open Terminal 2
        print("[*] Opening Terminal 2...")
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
        
        time.sleep(40)
        print("[+] Terminal opened")
        
        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        time.sleep(15)
        
        # Now explore the terminal content
        print("\n[*] Exploring terminal content...")
        
        # Get terminal text content
        try:
            # Try to get text from xterm rows
            text = driver.execute_script("""
                var rows = document.querySelectorAll('.xterm-rows div');
                var content = [];
                for (var i = 0; i < rows.length; i++) {
                    var line = rows[i].textContent.trim();
                    if (line) content.push(line);
                }
                return content.join('\\n');
            """)
            print(f"\n[*] Terminal content:\n{text}\n")
        except Exception as e:
            print(f"[!] Could not get terminal text: {e}")
        
        # Get full body text
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"\n[*] Body text:\n{body_text[:1000]}\n")
        
        # Look for links, URLs, webpages
        import re
        urls = re.findall(r'https?://[^\s<>"\']+', body_text)
        print(f"[*] Found URLs: {urls}")
        
        # Look for any clickable elements
        links = driver.find_elements(By.TAG_NAME, "a")
        print(f"\n[*] Found {len(links)} links in terminal")
        for link in links[:10]:
            try:
                href = link.get_attribute("href")
                text = link.text
                print(f"  - {text}: {href}")
            except:
                pass
        
        # Look for any tabs or tab-like elements
        tabs = driver.find_elements(By.CSS_SELECTOR, ".tab, [role='tab'], .nav-tab")
        print(f"\n[*] Found {len(tabs)} tabs")
        
        # Look for forms or inputs
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} inputs")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t2_content.png")
        print("\n[+] Screenshot saved: t2_content.png")
        
        # Save HTML
        html = driver.page_source
        with open("/home/claw/.openclaw/workspace/sans-challenge/t2_terminal.html", "w") as f:
            f.write(html)
        print("[+] HTML saved: t2_terminal.html")
        
        # Look for challenge instructions
        if "defang" in body_text.lower():
            print("\n[*] Challenge involves defanging")
            # Look for specific instructions
            lines = body_text.split('\n')
            for line in lines:
                if 'defang' in line.lower() or 'url' in line.lower() or 'http' in line.lower():
                    print(f"  > {line}")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
