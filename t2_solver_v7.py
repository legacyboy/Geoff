#!/usr/bin/env python3
"""
SANS HHC 2025 Terminal 2 "It's All About Defang" solver
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
import time

def main():
    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    
    driver = webdriver.Firefox(options=options)
    
    try:
        print("STEP 1: Login")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(2)
        
        # Close welcome modal
        WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.ID, "close-modal-btn"))
        ).click()
        time.sleep(1)
        
        # Login
        driver.find_element(By.NAME, "email").send_keys("danoclawnor@gmail.com")
        driver.find_element(By.NAME, "password").send_keys("hWu}2!dY?~JY8rc")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(4)
        
        print("STEP 2: Go to Objectives")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(3)
        
        # Scroll down to find Terminal 2
        print("STEP 3: Scroll to find Terminal 2")
        for i in range(10):
            driver.execute_script(f"window.scrollTo(0, {i * 300});")
            time.sleep(0.5)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v7_scroll_{i}.png")
            
            # Check if Terminal 2 is visible
            page_text = driver.find_element(By.TAG_NAME, "body").text
            if "Terminal 2" in page_text or "Its All About Defang" in page_text:
                print(f"Found Terminal 2 at scroll position {i}!")
                break
        
        # Get all links and find Terminal 2
        print("STEP 4: Find Terminal 2 link")
        links = driver.find_elements(By.TAG_NAME, "a")
        for link in links:
            text = link.text.strip()
            if "terminal" in text.lower() or "defang" in text.lower():
                print(f"Found: '{text}'")
                driver.execute_script("arguments[0].scrollIntoView(true);", link)
                time.sleep(1)
                link.click()
                time.sleep(3)
                driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v7_terminal_open.png")
                break
        
        print("STEP 5: Look for terminal button")
        # Get page content
        page_text = driver.find_element(By.TAG_NAME, "body").text
        with open("/home/claw/.openclaw/workspace/t2_v7_page.txt", "w") as f:
            f.write(page_text)
        print(f"Page content:\n{page_text[:1500]}")
        
        # Look for any button that might open the terminal
        buttons = driver.find_elements(By.TAG_NAME, "button")
        for btn in buttons:
            text = btn.text.strip()
            print(f"Button: '{text}'")
            if text and ("terminal" in text.lower() or "open" in text.lower() or "start" in text.lower()):
                print(f"  -> Clicking button: '{text}'")
                btn.click()
                time.sleep(3)
                driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v7_after_button_click.png")
        
        print("STEP 6: Check for iframe or terminal content")
        print(f"Current URL: {driver.current_url}")
        
        # Check for iframes
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"  Iframe {i}: {src}")
            
            driver.switch_to.frame(iframe)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v7_iframe_{i}.png")
            
            # Get iframe content
            text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v7_iframe_{i}.txt", "w") as f:
                f.write(text)
            print(f"  Iframe text: {text[:1000]}")
            
            # Look for tabs, inputs, buttons
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab")
            inputs = driver.find_elements(By.TAG_NAME, "input")
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            buttons = driver.find_elements(By.TAG_NAME, "button")
            
            print(f"  Found: {len(tabs)} tabs, {len(inputs)} inputs, {len(textareas)} textareas, {len(buttons)} buttons")
            
            for tab in tabs:
                print(f"    Tab: '{tab.text}'")
            for inp in inputs:
                print(f"    Input: type={inp.get_attribute('type')} id={inp.get_attribute('id')}")
            
            driver.switch_to.default_content()
        
        print("Done - review screenshots and text files")
        time.sleep(5)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v7_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
