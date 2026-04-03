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

def wait_and_find(driver, by, value, timeout=10):
    """Wait for element and return it"""
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((by, value))
    )

def wait_and_click(driver, by, value, timeout=10):
    """Wait for element to be clickable and click it"""
    elem = WebDriverWait(driver, timeout).until(
        EC.element_to_be_clickable((by, value))
    )
    elem.click()
    return elem

def main():
    # Setup Firefox
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step1_login.png")
        
        # Click login/sign in
        login_btn = wait_and_click(driver, By.LINK_TEXT, "Login")
        time.sleep(1)
        
        # Enter credentials
        email_field = wait_and_find(driver, By.ID, "username")
        email_field.send_keys("danoclawnor@gmail.com")
        
        password_field = driver.find_element(By.ID, "password")
        password_field.send_keys("hWu}2!dY?~JY8rc")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step1b_credentials.png")
        
        # Click submit
        submit_btn = driver.find_element(By.NAME, "action")
        submit_btn.click()
        
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step1c_logged_in.png")
        print("Login complete")
        
        print("=" * 60)
        print("STEP 2: Navigate to CTF Mode")
        print("=" * 60)
        
        # Click Play Now
        play_now = wait_and_click(driver, By.LINK_TEXT, "Play Now")
        time.sleep(2)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step2_play_now.png")
        
        # Click CTF Mode
        ctf_mode = wait_and_click(driver, By.LINK_TEXT, "CTF Mode")
        time.sleep(2)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step2b_ctf_mode.png")
        print("CTF Mode loaded")
        
        print("=" * 60)
        print("STEP 3: Navigate to Terminal 2 Badge")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step3_badge_objective.png")
        print("Badge objective page loaded")
        
        print("=" * 60)
        print("STEP 4: Find and open Terminal 2")
        print("=" * 60)
        
        # Look for Terminal 2 or "It's All About Defang"
        page_source = driver.page_source
        
        # Try to find Terminal 2 button/link
        try:
            # Look for Terminal 2 in various ways
            terminal_links = driver.find_elements(By.XPATH, "//a[contains(text(), 'Terminal 2') or contains(@href, 'terminal')]")
            print(f"Found {len(terminal_links)} terminal links")
            
            for i, link in enumerate(terminal_links):
                print(f"  Link {i}: {link.text} - {link.get_attribute('href')}")
        except Exception as e:
            print(f"Error finding terminal links: {e}")
        
        # Scroll to find Terminal 2
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step4_scrolled.png")
        
        # Try clicking on Terminal 2
        try:
            terminal2 = driver.find_element(By.XPATH, "//*[contains(text(), 'Terminal 2') or contains(text(), \"It's All About Defang\")]")
            terminal2.click()
            time.sleep(2)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step4b_terminal2_clicked.png")
        except Exception as e:
            print(f"Could not find Terminal 2 link: {e}")
            # Try direct navigation
            driver.get("https://2025.holidayhackchallenge.com/terminal")
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step4c_terminal_direct.png")
        
        print("=" * 60)
        print("STEP 5: Explore the terminal - READ EVERYTHING")
        print("=" * 60)
        
        # Take multiple screenshots to see the full terminal
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_step5_terminal_full.png")
        
        # Get page source to understand structure
        page_html = driver.page_source
        with open("/home/claw/.openclaw/workspace/t2_terminal_page.html", "w") as f:
            f.write(page_html)
        print("Saved terminal page HTML")
        
        # Look for iframes (the terminal might be in one)
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"  Iframe {i}: {src}")
            
            # Switch to iframe and explore
            driver.switch_to.frame(iframe)
            time.sleep(1)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_step5_iframe_{i}.png")
            
            # Get content inside iframe
            iframe_html = driver.page_source
            with open(f"/home/claw/.openclaw/workspace/t2_iframe_{i}_content.html", "w") as f:
                f.write(iframe_html)
            print(f"  Saved iframe {i} content")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, [class*='tab']")
            print(f"    Found {len(tabs)} tabs in iframe {i}")
            for j, tab in enumerate(tabs):
                print(f"      Tab {j}: {tab.text}")
            
            # Look for input fields
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"    Found {len(inputs)} input fields in iframe {i}")
            for j, inp in enumerate(inputs):
                input_type = inp.get_attribute("type")
                placeholder = inp.get_attribute("placeholder")
                name = inp.get_attribute("name")
                print(f"      Input {j}: type={input_type}, placeholder={placeholder}, name={name}")
            
            # Switch back
            driver.switch_to.default_content()
        
        print("=" * 60)
        print("Exploration complete - check screenshots and HTML files")
        print("=" * 60)
        
        # Keep browser open for manual inspection if needed
        time.sleep(10)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_error.png")
    
    finally:
        input("Press Enter to close browser...")
        driver.quit()

if __name__ == "__main__":
    main()
