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
        print("STEP 2: Click Play Now button")
        print("=" * 60)
        
        # Find and click the Play Now button
        play_now_btn = wait_and_click(driver, By.XPATH, "//button[contains(text(), 'Play Now')]")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_step2_playnow.png")
        print("Clicked Play Now")
        
        print("=" * 60)
        print("STEP 3: Find Badge/Objectives link")
        print("=" * 60)
        
        # Look for Badge link or Objectives
        all_links = driver.find_elements(By.TAG_NAME, "a")
        print(f"Found {len(all_links)} links:")
        for link in all_links:
            text = link.text.strip()
            href = link.get_attribute("href") or ""
            print(f"  '{text}' -> {href}")
            if "badge" in text.lower():
                print(f"    ^^^ FOUND BADGE LINK")
                link.click()
                time.sleep(3)
                break
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_step3_after_badge_click.png")
        
        print("=" * 60)
        print("STEP 4: Navigate to objectives section")
        print("=" * 60)
        
        # Try clicking on Objectives tab
        try:
            objectives_tab = driver.find_element(By.XPATH, "//*[contains(text(), 'Objectives')]")
            objectives_tab.click()
            time.sleep(2)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_step4_objectives.png")
        except Exception as e:
            print(f"Could not find Objectives tab: {e}")
        
        # Navigate directly to badge objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(4)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_step4_direct_objective.png")
        print(f"Current URL: {driver.current_url}")
        
        print("=" * 60)
        print("STEP 5: Find Terminal 2")
        print("=" * 60)
        
        # Get all text on the page
        page_text = driver.find_element(By.TAG_NAME, "body").text
        with open("/home/claw/.openclaw/workspace/t2_v5_page_text.txt", "w") as f:
            f.write(page_text)
        
        # Check for Terminal 2
        if "Terminal 2" in page_text:
            print("Found Terminal 2 in page text!")
            # Find the context around Terminal 2
            lines = page_text.split('\n')
            for i, line in enumerate(lines):
                if "Terminal 2" in line:
                    print(f"  Line {i}: {line}")
                    print(f"  Context: {lines[max(0,i-3):i+4]}")
        
        if "It's All About Defang" in page_text:
            print("Found 'It's All About Defang' in page text!")
        
        # Look for all buttons and links
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"\nFound {len(buttons)} buttons")
        for btn in buttons:
            text = btn.text.strip()
            if text:
                print(f"  Button: '{text}'")
        
        links = driver.find_elements(By.TAG_NAME, "a")
        print(f"\nFound {len(links)} links")
        for link in links:
            text = link.text.strip()
            if text:
                print(f"  Link: '{text}'")
        
        # Try to find clickable Terminal 2 element
        try:
            t2_elem = driver.find_element(By.XPATH, "//*[contains(text(), 'Terminal 2')]/..")
            print(f"Found Terminal 2 parent element: {t2_elem.tag_name}")
            t2_elem.click()
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_step5_terminal_clicked.png")
        except Exception as e:
            print(f"Could not find/click Terminal 2: {e}")
        
        print("=" * 60)
        print("STEP 6: Check if we're in terminal")
        print("=" * 60)
        
        # Check current URL
        current_url = driver.current_url
        print(f"Current URL: {current_url}")
        
        # Check for iframes
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"  Iframe {i}: {src}")
            
            driver.switch_to.frame(iframe)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v5_iframe_{i}.png")
            
            # Get iframe content
            iframe_text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v5_iframe_{i}_text.txt", "w") as f:
                f.write(iframe_text)
            
            print(f"    Iframe text preview: {iframe_text[:500]}")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, .nav-link, button")
            print(f"    Found {len(tabs)} potential tabs/interactables")
            for j, tab in enumerate(tabs[:15]):
                print(f"      Tab {j}: '{tab.text}' class={tab.get_attribute('class')}")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            print(f"    Found {len(inputs)} inputs and {len(textareas)} textareas")
            for inp in inputs:
                print(f"      Input: type={inp.get_attribute('type')} id={inp.get_attribute('id')}")
            
            driver.switch_to.default_content()
        
        print("=" * 60)
        print("Exploration complete")
        print("=" * 60)
        
        time.sleep(5)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v5_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
