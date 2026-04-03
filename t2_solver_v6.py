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
        
        # Close the welcome modal
        close_btn = wait_and_click(driver, By.ID, "close-modal-btn")
        time.sleep(1)
        
        # Enter credentials
        email_field = wait_and_find(driver, By.NAME, "email")
        email_field.clear()
        email_field.send_keys("danoclawnor@gmail.com")
        
        password_field = driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("hWu}2!dY?~JY8rc")
        
        submit_btn = driver.find_element(By.XPATH, "//button[@type='submit']")
        submit_btn.click()
        
        time.sleep(4)
        print("Login complete")
        
        print("=" * 60)
        print("STEP 2: Navigate to Objectives")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v6_step2_objectives.png")
        
        print("=" * 60)
        print("STEP 3: Click on 'Its All About Defang'")
        print("=" * 60)
        
        # Find and click on "Its All About Defang" (no apostrophe!)
        defang_link = wait_and_click(driver, By.XPATH, "//*[contains(text(), 'Its All About Defang')]")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v6_step3_defang_open.png")
        
        print("Opened 'Its All About Defang' objective")
        
        print("=" * 60)
        print("STEP 4: Find and open terminal")
        print("=" * 60)
        
        # Get page content
        page_text = driver.find_element(By.TAG_NAME, "body").text
        with open("/home/claw/.openclaw/workspace/t2_v6_defang_page.txt", "w") as f:
            f.write(page_text)
        print(f"Page text saved. Content preview:\n{page_text[:2000]}")
        
        # Look for terminal button/link
        # Try finding by text containing "Terminal" or "Open Terminal"
        try:
            terminal_btn = driver.find_element(By.XPATH, "//*[contains(text(), 'Open Terminal') or contains(text(), 'Start Terminal') or contains(text(), 'Terminal')]")
            print(f"Found terminal button: '{terminal_btn.text}'")
            terminal_btn.click()
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v6_step4_terminal_open.png")
        except Exception as e:
            print(f"Could not find terminal button by text: {e}")
            
            # Look for all buttons
            buttons = driver.find_elements(By.TAG_NAME, "button")
            print(f"Found {len(buttons)} buttons:")
            for i, btn in enumerate(buttons):
                text = btn.text.strip()
                print(f"  Button {i}: '{text}'")
                if "terminal" in text.lower() or "open" in text.lower() or "start" in text.lower():
                    print(f"    ^^^ CLICKING THIS BUTTON")
                    btn.click()
                    time.sleep(3)
                    driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v6_step4_button_{i}.png")
        
        print("=" * 60)
        print("STEP 5: Explore the terminal interface")
        print("=" * 60)
        
        # Check current URL
        print(f"Current URL: {driver.current_url}")
        
        # Look for iframes (terminal is likely in an iframe)
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"\n  Iframe {i}: {src}")
            
            driver.switch_to.frame(iframe)
            time.sleep(1)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v6_iframe_{i}.png")
            
            # Save iframe HTML
            iframe_html = driver.page_source
            with open(f"/home/claw/.openclaw/workspace/t2_v6_iframe_{i}.html", "w") as f:
                f.write(iframe_html)
            
            # Get iframe text
            iframe_text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v6_iframe_{i}_text.txt", "w") as f:
                f.write(iframe_text)
            print(f"    Iframe text length: {len(iframe_text)}")
            print(f"    Preview: {iframe_text[:1000]}...")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, .nav-link, button[class*='tab'], a[class*='tab']")
            print(f"    Found {len(tabs)} potential tabs")
            for j, tab in enumerate(tabs):
                text = tab.text.strip()
                if text:
                    print(f"      Tab {j}: '{text}' (tag={tab.tag_name}, class={tab.get_attribute('class')})")
            
            # Look for all clickable elements
            clickables = driver.find_elements(By.CSS_SELECTOR, "button, a, [role='button']")
            print(f"    Found {len(clickables)} clickable elements")
            for j, elem in enumerate(clickables[:15]):
                text = elem.text.strip()
                if text:
                    print(f"      Clickable {j}: '{text}' ({elem.tag_name})")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            print(f"    Found {len(inputs)} inputs and {len(textareas)} textareas")
            for inp in inputs:
                input_type = inp.get_attribute("type")
                input_id = inp.get_attribute("id")
                input_name = inp.get_attribute("name")
                input_placeholder = inp.get_attribute("placeholder")
                print(f"      Input: type={input_type}, id={input_id}, name={input_name}, placeholder={input_placeholder}")
            
            driver.switch_to.default_content()
        
        print("=" * 60)
        print("STEP 6: If no iframe, explore main content")
        print("=" * 60)
        
        if len(iframes) == 0:
            print("No iframes found - exploring main content...")
            
            # Get all text
            body_text = driver.find_element(By.TAG_NAME, "body").text
            with open("/home/claw/.openclaw/workspace/t2_v6_main_content.txt", "w") as f:
                f.write(body_text)
            print(f"Main content:\n{body_text[:2000]}")
            
            # Look for tabs in main content
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, .nav-link")
            print(f"Found {len(tabs)} tabs in main content")
            for tab in tabs:
                print(f"  Tab: '{tab.text}'")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"Found {len(inputs)} inputs")
            for inp in inputs:
                print(f"  Input: id={inp.get_attribute('id')}, name={inp.get_attribute('name')}")
        
        print("=" * 60)
        print("STEP 7: Check achievements for completion")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v6_step7_achievements.png")
        
        achievements_text = driver.find_element(By.TAG_NAME, "body").text
        if "It's All About Defang" in achievements_text or "Its All About Defang" in achievements_text:
            print("ACHIEVEMENT FOUND! Challenge completed!")
        else:
            print("Achievement not yet completed")
        
        print("=" * 60)
        print("Exploration complete - review all files and screenshots")
        print("=" * 60)
        
        time.sleep(10)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v6_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
