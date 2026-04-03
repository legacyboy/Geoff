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
    wait = WebDriverWait(driver, 15)
    
    try:
        print("STEP 1: Login")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(2)
        
        # Check current URL
        print(f"After loading main page: {driver.current_url}")
        
        # Close welcome modal if present
        try:
            close_btn = WebDriverWait(driver, 5).until(
                EC.element_to_be_clickable((By.ID, "close-modal-btn"))
            )
            close_btn.click()
            time.sleep(1)
            print("Closed welcome modal")
        except:
            print("No welcome modal found")
        
        # Check if already on login form
        print(f"Current URL: {driver.current_url}")
        
        # Fill in login form
        email_field = driver.find_element(By.NAME, "email")
        email_field.clear()
        email_field.send_keys("danoclawnor@gmail.com")
        
        password_field = driver.find_element(By.NAME, "password")
        password_field.clear()
        password_field.send_keys("hWu}2!dY?~JY8rc")
        
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(5)
        
        print(f"After login: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_after_login.png")
        
        print("STEP 2: Click Play Now to enter game")
        # Click Play Now button
        play_now = driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]")
        play_now.click()
        time.sleep(5)
        
        print(f"After Play Now: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_after_playnow.png")
        
        print("STEP 3: Navigate to Badge/Objectives")
        # Try to find Badge link
        try:
            badge_link = driver.find_element(By.XPATH, "//a[contains(@href, 'badge')]")
            print(f"Found badge link: {badge_link.get_attribute('href')}")
            badge_link.click()
            time.sleep(4)
        except:
            print("No badge link found, navigating directly")
            driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
            time.sleep(4)
        
        print(f"Current URL: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_badge_page.png")
        
        # Save page HTML
        with open("/home/claw/.openclaw/workspace/t2_v8_badge_html.html", "w") as f:
            f.write(driver.page_source)
        
        print("STEP 4: Look for Terminal 2 in page content")
        page_text = driver.find_element(By.TAG_NAME, "body").text
        with open("/home/claw/.openclaw/workspace/t2_v8_page_text.txt", "w") as f:
            f.write(page_text)
        print(f"Page text:\n{page_text}")
        
        # Look for "Terminal 2" or "Its All About Defang"
        if "Terminal 2" in page_text or "Its All About Defang" in page_text:
            print("Found Terminal 2 in page!")
        else:
            print("Terminal 2 not in page text")
        
        print("STEP 5: Find and click on Terminal 2")
        # Try different selectors to find Terminal 2
        selectors = [
            "//*[contains(text(), 'Terminal 2')]",
            "//*[contains(text(), 'Its All About Defang')]",
            "//a[contains(text(), 'Terminal')]",
            "//div[contains(text(), 'Defang')]",
        ]
        
        for selector in selectors:
            try:
                elem = driver.find_element(By.XPATH, selector)
                print(f"Found element with selector '{selector}': '{elem.text}'")
                driver.execute_script("arguments[0].scrollIntoView(true);", elem)
                time.sleep(1)
                elem.click()
                time.sleep(3)
                driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_terminal_clicked.png")
                break
            except Exception as e:
                print(f"Selector '{selector}' failed: {e}")
        
        print(f"After clicking: {driver.current_url}")
        
        print("STEP 6: Look for terminal interface")
        # Check for iframes
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"Iframe {i}: {src}")
            driver.switch_to.frame(iframe)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v8_iframe_{i}.png")
            
            # Get content
            text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v8_iframe_{i}.txt", "w") as f:
                f.write(text)
            print(f"Iframe {i} text: {text[:1500]}")
            
            # Look for all elements
            all_elems = driver.find_elements(By.XPATH, "//*")
            print(f"Found {len(all_elems)} elements in iframe")
            
            # Look for tabs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab']")
            print(f"Found {len(tabs)} tabs")
            for tab in tabs:
                print(f"  Tab: '{tab.text}'")
            
            # Look for inputs
            inputs = driver.find_elements(By.TAG_NAME, "input")
            print(f"Found {len(inputs)} inputs")
            for inp in inputs:
                print(f"  Input: type={inp.get_attribute('type')}, id={inp.get_attribute('id')}")
            
            driver.switch_to.default_content()
        
        print("STEP 7: Check achievements")
        driver.get("https://2025.holidayhackchallenge.com/badge?section=achievement")
        time.sleep(3)
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_achievements.png")
        
        print("Done!")
        time.sleep(5)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v8_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
