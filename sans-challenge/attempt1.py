#!/usr/bin/env python3
"""
SANS HHC 2025 - termOrientation Challenge
Automates login, enables CTF mode, navigates to Objectives, opens terminal,
and types "answer" in the UPPER challenge input box.
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time

# Configuration
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"
BASE_URL = "https://2025.holidayhackchallenge.com"

def setup_driver():
    """Set up Chrome driver with appropriate options."""
    chrome_options = Options()
    # chrome_options.add_argument("--headless")  # Keep visible to see what's happening
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("--disable-blink-features=AutomationControlled")
    chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
    chrome_options.add_experimental_option('useAutomationExtension', False)
    
    driver = webdriver.Chrome(options=chrome_options)
    driver.execute_script("Object.defineProperty(navigator, 'webdriver', {get: () => undefined})")
    driver.maximize_window()
    return driver

def safe_click(driver, element):
    """Click an element safely, handling intercept issues."""
    try:
        # Scroll into view first
        driver.execute_script("arguments[0].scrollIntoView({block: 'center'});", element)
        time.sleep(0.5)
        # Try regular click
        element.click()
    except Exception as e:
        # Fallback to JavaScript click
        driver.execute_script("arguments[0].click();", element)

def login(driver, wait):
    """Login to the SANS HHC website."""
    print("Navigating to login page...")
    driver.get(f"{BASE_URL}/login")
    
    time.sleep(3)
    
    # Take screenshot to see what's on the page
    driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/login_page.png")
    
    print("Entering credentials...")
    # Find email field - try multiple selectors
    email_field = None
    selectors = [
        "input[type='email']",
        "input[name='email']",
        "input#email",
        "input[placeholder*='email' i]",
        "input[placeholder*='Email' i]"
    ]
    for selector in selectors:
        try:
            email_field = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, selector)))
            print(f"Found email field with selector: {selector}")
            break
        except:
            continue
    
    if not email_field:
        # Try finding any input field that might be email
        inputs = driver.find_elements(By.TAG_NAME, "input")
        for inp in inputs:
            if inp.get_attribute("type") in ["email", "text"]:
                email_field = inp
                print(f"Found email field by tag: {inp.get_attribute('outerHTML')[:100]}")
                break
    
    if email_field:
        email_field.clear()
        email_field.send_keys(EMAIL)
        print("Email entered")
    else:
        raise Exception("Could not find email field")
    
    # Find password field
    password_field = None
    pass_selectors = [
        "input[type='password']",
        "input[name='password']",
        "input#password"
    ]
    for selector in pass_selectors:
        try:
            password_field = driver.find_element(By.CSS_SELECTOR, selector)
            break
        except:
            continue
    
    if not password_field:
        inputs = driver.find_elements(By.TAG_NAME, "input")
        for inp in inputs:
            if inp.get_attribute("type") == "password":
                password_field = inp
                break
    
    if password_field:
        password_field.clear()
        password_field.send_keys(PASSWORD)
        print("Password entered")
    else:
        raise Exception("Could not find password field")
    
    # Find and click login button
    login_button = None
    btn_selectors = [
        "button[type='submit']",
        "input[type='submit']",
        "button.btn-primary",
        "button.login-btn",
        "button"
    ]
    for selector in btn_selectors:
        try:
            login_button = driver.find_element(By.CSS_SELECTOR, selector)
            print(f"Found login button with selector: {selector}")
            break
        except:
            continue
    
    if login_button:
        print("Clicking login button...")
        safe_click(driver, login_button)
    else:
        raise Exception("Could not find login button")
    
    print("Login submitted, waiting...")
    time.sleep(4)
    
    # Take screenshot after login
    driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_login.png")

def enable_ctf_mode(driver, wait):
    """Enable CTF mode in settings."""
    print("Navigating to CTF settings...")
    driver.get(f"{BASE_URL}/badge?section=setting")
    
    time.sleep(3)
    driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/settings_page.png")
    
    print("Looking for CTF mode toggle...")
    # Try to find CTF mode toggle
    try:
        # Look for checkboxes
        checkboxes = driver.find_elements(By.CSS_SELECTOR, "input[type='checkbox']")
        print(f"Found {len(checkboxes)} checkboxes")
        
        for cb in checkboxes:
            # Check if it's CTF related
            parent = cb.find_element(By.XPATH, "..")
            grandparent = parent.find_element(By.XPATH, "..")
            text_content = (parent.text + " " + grandparent.text).lower()
            
            if "ctf" in text_content:
                print(f"Found CTF checkbox, text: {text_content[:100]}")
                if not cb.is_selected():
                    safe_click(driver, cb)
                    print("CTF mode enabled")
                else:
                    print("CTF mode already enabled")
                break
        else:
            print("No specific CTF checkbox found, may already be enabled")
            
    except Exception as e:
        print(f"Warning: Could not enable CTF mode: {e}")
    
    time.sleep(1)

def navigate_to_objectives(driver, wait):
    """Navigate to the Objectives page."""
    print("Navigating to Objectives...")
    driver.get(f"{BASE_URL}/objectives")
    
    time.sleep(3)
    driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/objectives_page.png")

def open_terminal(driver, wait):
    """Click 'Open Terminal' button."""
    print("Looking for 'Open Terminal' button...")
    
    # Try multiple selectors
    terminal_btn = None
    selectors = [
        (By.XPATH, "//button[contains(text(), 'Open Terminal')]"),
        (By.XPATH, "//button[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'terminal')]"),
        (By.XPATH, "//a[contains(text(), 'Open Terminal')]"),
        (By.CSS_SELECTOR, "button.terminal-btn"),
        (By.CSS_SELECTOR, "button.btn-terminal"),
        (By.CSS_SELECTOR, "[data-action='open-terminal']")
    ]
    
    for by, selector in selectors:
        try:
            terminal_btn = wait.until(EC.element_to_be_clickable((by, selector)))
            print(f"Found terminal button with selector: {selector}")
            break
        except:
            continue
    
    if terminal_btn:
        safe_click(driver, terminal_btn)
        print("Clicked Open Terminal")
    else:
        print("Terminal button not found with standard selectors, taking screenshot...")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/terminal_not_found.png")
    
    time.sleep(3)

def find_upper_challenge_input(driver, wait):
    """Find and type in the UPPER challenge input box."""
    print("Looking for UPPER challenge input box...")
    driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/before_upper_input.png")
    
    # Look for UPPER challenge specifically - NOT the shell input
    upper_input = None
    selectors = [
        (By.XPATH, "//input[contains(translate(@placeholder, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'upper')]"),
        (By.XPATH, "//input[contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'upper')]"),
        (By.XPATH, "//input[contains(translate(@id, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'upper')]"),
        (By.XPATH, "//label[contains(translate(text(), 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'upper')]//following::input[1]"),
        (By.XPATH, "//div[contains(translate(., 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'), 'upper')]//input"),
        (By.CSS_SELECTOR, "input.upper-input"),
        (By.CSS_SELECTOR, "input[data-challenge='upper']"),
    ]
    
    for by, selector in selectors:
        try:
            upper_input = wait.until(EC.presence_of_element_located((by, selector)))
            print(f"Found UPPER input with selector: {selector}")
            break
        except:
            continue
    
    if not upper_input:
        # Try to find any input that looks like it could be the answer input
        print("Trying to find any relevant input fields...")
        inputs = driver.find_elements(By.CSS_SELECTOR, "input[type='text']")
        print(f"Found {len(inputs)} text inputs")
        
        for inp in inputs:
            try:
                # Check if it's NOT a shell/command input
                placeholder = inp.get_attribute("placeholder") or ""
                id_attr = inp.get_attribute("id") or ""
                class_attr = inp.get_attribute("class") or ""
                
                # Look for anything mentioning upper/answer/challenge
                if any(word in (placeholder + id_attr + class_attr).lower() for word in ['upper', 'answer', 'challenge', 'submit', 'flag']):
                    upper_input = inp
                    print(f"Found potential UPPER input: placeholder={placeholder}, id={id_attr}, class={class_attr}")
                    break
            except:
                continue
    
    if upper_input:
        print("Found UPPER challenge input, typing 'answer'...")
        upper_input.clear()
        upper_input.send_keys("answer")
        print("Typed 'answer' in the UPPER challenge input box")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/after_typing_answer.png")
    else:
        print("Could not find UPPER challenge input")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/upper_not_found.png")

def main():
    print("=" * 60)
    print("SANS HHC 2025 - termOrientation Challenge")
    print("=" * 60)
    
    driver = None
    try:
        driver = setup_driver()
        wait = WebDriverWait(driver, 15)
        
        # Step 1: Login
        login(driver, wait)
        
        # Step 2: Enable CTF mode
        enable_ctf_mode(driver, wait)
        
        # Step 3: Navigate to Objectives
        navigate_to_objectives(driver, wait)
        
        # Step 4: Click Open Terminal
        open_terminal(driver, wait)
        
        # Step 5: Find UPPER challenge input and type "answer"
        find_upper_challenge_input(driver, wait)
        
        print("\n" + "=" * 60)
        print("Script completed!")
        print("=" * 60)
        
        # Keep the browser open for inspection
        print("\nBrowser will remain open for 30 seconds...")
        time.sleep(30)
        
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        if driver:
            print("\nTaking screenshot of current state...")
            driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/error_screenshot.png")
            print("Screenshot saved to error_screenshot.png")
    finally:
        if driver:
            print("\nClosing browser...")
            driver.quit()

if __name__ == "__main__":
    main()
