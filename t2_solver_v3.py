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
    """Wait for element and return it"""
    return WebDriverWait(driver, timeout).until(
        EC.presence_of_element_located((by, value))
    )

def wait_and_click(driver, by, value, timeout=15):
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step1_main.png")
        
        # Close the welcome modal first
        print("Closing welcome modal...")
        close_btn = wait_and_click(driver, By.ID, "close-modal-btn")
        time.sleep(1)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step1b_modal_closed.png")
        
        # Now enter credentials
        email_field = wait_and_find(driver, By.NAME, "email")
        email_field.clear()
        email_field.send_keys("danoclawnor@gmail.com")
        
        password_field = driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("hWu}2!dY?~JY8rc")
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step1c_credentials.png")
        
        # Click submit - "Sign In" button
        submit_btn = driver.find_element(By.XPATH, "//button[@type='submit']")
        submit_btn.click()
        
        time.sleep(4)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step1d_logged_in.png")
        print("Login complete")
        
        print("=" * 60)
        print("STEP 2: Navigate to CTF Mode")
        print("=" * 60)
        
        # Click Play Now
        play_now = wait_and_click(driver, By.LINK_TEXT, "Play Now")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step2_play_now.png")
        
        # Click CTF Mode
        ctf_mode = wait_and_click(driver, By.LINK_TEXT, "CTF Mode")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step2b_ctf_mode.png")
        print("CTF Mode loaded")
        
        print("=" * 60)
        print("STEP 3: Navigate to Terminal 2 Badge")
        print("=" * 60)
        
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step3_badge_objective.png")
        print("Badge objective page loaded")
        
        # Save the page HTML to understand structure
        with open("/home/claw/.openclaw/workspace/t2_v3_badge_page.html", "w") as f:
            f.write(driver.page_source)
        
        print("=" * 60)
        print("STEP 4: Find and open Terminal 2")
        print("=" * 60)
        
        # Scroll to find Terminal 2
        driver.execute_script("window.scrollTo(0, document.body.scrollHeight);")
        time.sleep(1)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step4_scrolled.png")
        
        # Look for Terminal 2 link/button - search for all links
        all_links = driver.find_elements(By.TAG_NAME, "a")
        print(f"\nAll links on page:")
        for link in all_links:
            text = link.text.strip()
            href = link.get_attribute("href")
            if text and "terminal" in text.lower():
                print(f"  TERMINAL LINK: '{text}' -> {href}")
        
        # Try to find Terminal 2
        try:
            # Try to find by text
            terminal2 = driver.find_element(By.XPATH, "//*[contains(text(), 'Terminal 2')]")
            print(f"\nFound Terminal 2 element: {terminal2.tag_name}")
            terminal2.click()
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step4b_terminal2_open.png")
        except Exception as e:
            print(f"\nCould not find Terminal 2 by text: {e}")
            try:
                # Try finding "It's All About Defang"
                terminal2 = driver.find_element(By.XPATH, "//*[contains(text(), \"It's All About Defang\")]")
                print(f"Found 'It's All About Defang' element: {terminal2.tag_name}")
                terminal2.click()
                time.sleep(3)
                driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step4c_defang_open.png")
            except Exception as e2:
                print(f"Could not find by defang text: {e2}")
        
        print("=" * 60)
        print("STEP 5: Explore the terminal - READ EVERYTHING")
        print("=" * 60)
        
        # Take multiple screenshots to see the full terminal
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_step5_terminal_full.png")
        
        # Get page source to understand structure
        page_html = driver.page_source
        with open("/home/claw/.openclaw/workspace/t2_v3_terminal_page.html", "w") as f:
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
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v3_step5_iframe_{i}.png")
            
            # Get content inside iframe
            iframe_html = driver.page_source
            with open(f"/home/claw/.openclaw/workspace/t2_v3_iframe_{i}_content.html", "w") as f:
                f.write(iframe_html)
            print(f"  Saved iframe {i} content")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab, [class*='tab']")
            print(f"    Found {len(tabs)} tabs in iframe {i}")
            for j, tab in enumerate(tabs):
                print(f"      Tab {j}: text='{tab.text}', class='{tab.get_attribute('class')}'")
            
            # Look for input fields
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"    Found {len(inputs)} input fields in iframe {i}")
            for j, inp in enumerate(inputs):
                input_type = inp.get_attribute("type")
                placeholder = inp.get_attribute("placeholder")
                name = inp.get_attribute("name")
                id_attr = inp.get_attribute("id")
                print(f"      Input {j}: type={input_type}, placeholder={placeholder}, name={name}, id={id_attr}")
            
            # Look for buttons
            buttons = driver.find_elements(By.TAG_NAME, "button")
            print(f"    Found {len(buttons)} buttons in iframe {i}")
            for j, btn in enumerate(buttons):
                print(f"      Button {j}: text='{btn.text}', type='{btn.get_attribute('type')}'")
            
            # Look for textareas
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            print(f"    Found {len(textareas)} textareas in iframe {i}")
            
            # Look for instructions or text content
            all_text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v3_iframe_{i}_text.txt", "w") as f:
                f.write(all_text)
            print(f"    Saved all text content from iframe {i}")
            
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
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v3_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
