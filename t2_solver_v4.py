#!/usr/bin/env python3
"""
SANS HHC 2025 Terminal 2 "It's All About Defang" solver
Methodical approach - read everything, identify all tabs and inputs
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
import time
import re

def wait_and_find(driver, by, value, timeout=15):
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((by, value))
    )

def wait_and_click(driver, by, value, timeout=15):
    elem = WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable((by, value))
    )
    elem.click()
    return elem

def main():
    options = Options()
    options.add_argument("--width=1920")
    options.add_argument("--height=1080")
    
    driver = webdriver.Firefox(options=options)
    wait = WebDriverWait(driver, 15)
    
    try:
        print("=" * 60)
        print("STEP 1: Login to SANS HHC")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(2)
        
        # Close the welcome modal first
        print("Closing welcome modal...")
        close_btn = wait_and_click(driver, By.ID, "close-modal-btn")
        time.sleep(1)
        
        # Now enter credentials
        email_field = wait_and_find(driver, By.NAME, "email")
        email_field.clear()
        email_field.send_keys("danoclawnor@gmail.com")
        
        password_field = driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("hWu}2!dY?~JY8rc")
        
        # Click submit
        submit_btn = driver.find_element(By.XPATH, "//button[@type='submit']")
        submit_btn.click()
        
        time.sleep(4)
        print("Login complete")
        
        print("=" * 60)
        print("STEP 2: Direct navigation to badge page")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(4)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step2_badge.png")
        
        # Scroll to see all objectives
        for scroll in range(5):
            driver.execute_script(f"window.scrollTo(0, {scroll * 500});")
            time.sleep(1)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_step2_scroll_{scroll}.png")
        
        print("Badge page loaded and scrolled")
        
        print("=" * 60)
        print("STEP 3: Find Terminal 2 / It's All About Defang")
        print("=" * 60)
        
        # Get all links
        all_links = driver.find_elements(By.TAG_NAME, "a")
        print(f"\nFound {len(all_links)} links on page")
        terminal_link = None
        for link in all_links:
            text = link.text.strip()
            href = link.get_attribute("href") or ""
            if text and ("terminal" in text.lower() or "defang" in text.lower()):
                print(f"  MATCH: '{text}' -> {href}")
                if not terminal_link:
                    terminal_link = link
        
        # Try to click Terminal 2
        if terminal_link:
            print(f"\nClicking on: {terminal_link.text}")
            driver.execute_script("arguments[0].scrollIntoView(true);", terminal_link)
            time.sleep(1)
            terminal_link.click()
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step3_terminal_clicked.png")
        else:
            print("No terminal link found, trying direct URL...")
            driver.get("https://2025.holidayhackchallenge.com/terminal")
            time.sleep(3)
        
        print("=" * 60)
        print("STEP 4: Explore the terminal - READ EVERYTHING")
        print("=" * 60)
        
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step4_terminal.png")
        
        # Save HTML
        with open("/home/claw/.openclaw/workspace/t2_terminal_page.html", "w") as f:
            f.write(driver.page_source)
        
        # Look for iframes
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"  Iframe {i}: {src}")
            
            driver.switch_to.frame(iframe)
            time.sleep(1)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_step4_iframe_{i}.png")
            
            iframe_html = driver.page_source
            with open(f"/home/claw/.openclaw/workspace/t2_iframe_{i}.html", "w") as f:
                f.write(iframe_html)
            
            # Get all text
            body_text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_iframe_{i}_text.txt", "w") as f:
                f.write(body_text)
            print(f"    Saved iframe {i} content and text")
            print(f"    Text preview: {body_text[:500]}...")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, button[class*='tab'], a[class*='tab']")
            print(f"    Found {len(tabs)} potential tabs")
            for j, tab in enumerate(tabs[:10]):  # Limit output
                print(f"      Tab {j}: '{tab.text}' class={tab.get_attribute('class')}")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            print(f"    Found {len(inputs)} inputs and {len(textareas)} textareas")
            for j, inp in enumerate(inputs[:10]):
                print(f"      Input {j}: type={inp.get_attribute('type')} id={inp.get_attribute('id')} name={inp.get_attribute('name')}")
            for j, ta in enumerate(textareas[:10]):
                print(f"      Textarea {j}: id={ta.get_attribute('id')} name={ta.get_attribute('name')}")
            
            # Look for buttons
            buttons = driver.find_elements(By.TAG_NAME, "button")
            print(f"    Found {len(buttons)} buttons")
            for j, btn in enumerate(buttons[:10]):
                print(f"      Button {j}: '{btn.text}' type={btn.get_attribute('type')}")
            
            driver.switch_to.default_content()
        
        print("=" * 60)
        print("STEP 5: Check achievements for completion status")
        print("=" * 60)
        
        # Save current state before checking achievements
        current_url = driver.current_url
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step5_achievements.png")
        
        # Look for "It's All About Defang" achievement
        page_text = driver.find_element(By.TAG_NAME, "body").text
        if "It's All About Defang" in page_text:
            print("SUCCESS: 'It's All About Defang' achievement found!")
            # Check if it's completed
            lines = page_text.split('\n')
            for i, line in enumerate(lines):
                if "It's All About Defang" in line:
                    print(f"  Context: {lines[max(0,i-2):i+3]}")
        else:
            print("'It's All About Defang' achievement not yet completed")
        
        print("=" * 60)
        print("Exploration complete!")
        print("=" * 60)
        
        time.sleep(5)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
