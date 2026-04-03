#!/usr/bin/env python3
"""
SANS HHC 2025 Terminal 2 "It's All About Defang" solver
Navigate to City Hall and find Terminal 2
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
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
        try:
            driver.find_element(By.ID, "close-modal-btn").click()
            time.sleep(1)
        except:
            pass
        
        # Login
        driver.find_element(By.NAME, "email").send_keys("danoclawnor@gmail.com")
        driver.find_element(By.NAME, "password").send_keys("hWu}2!dY?~JY8rc")
        driver.find_element(By.XPATH, "//button[@type='submit']").click()
        time.sleep(4)
        
        print("STEP 2: Click Play Now")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(5)
        
        print(f"Current location: {driver.current_url}")
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v9_step2_train.png")
        
        # Check if we're at the train
        page_text = driver.find_element(By.TAG_NAME, "body").text
        if "Train" in page_text:
            print("Currently at Train location")
        
        print("STEP 3: Navigate to City Hall")
        # Look for the door clicker to go to city
        # The door is in the 3D view, we need to click on it
        # Based on HTML: door-clicker one train-city
        
        # Try clicking on the center-right of the screen where the door should be
        # The 3D view is rendered with CSS transforms
        actions = ActionChains(driver)
        
        # Try clicking where the door might be (center-right of viewport)
        print("Attempting to navigate to City...")
        
        # Try finding and clicking the door clicker
        try:
            door = driver.find_element(By.CSS_SELECTOR, ".door-clicker.train-city")
            print(f"Found door clicker: {door.get_attribute('class')}")
            door.click()
            time.sleep(4)
        except Exception as e:
            print(f"Could not find door clicker: {e}")
            # Try clicking at coordinates where door might be
            actions.move_by_offset(1200, 500).click().perform()
            time.sleep(4)
        
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v9_step3_after_door.png")
        print(f"After door click: {driver.current_url}")
        
        # Check page text
        page_text = driver.find_element(By.TAG_NAME, "body").text
        with open("/home/claw/.openclaw/workspace/t2_v9_page_text.txt", "w") as f:
            f.write(page_text)
        print(f"Page text:\n{page_text[:2000]}")
        
        print("STEP 4: Look for Terminal 2 in City Hall")
        if "Terminal 2" in page_text or "City" in page_text or "Ed Skoudis" in page_text:
            print("Found relevant content!")
        
        # Look for Terminal 2 entity
        try:
            t2 = driver.find_element(By.CSS_SELECTOR, ".terminal-termDefang")
            print(f"Found Terminal 2 entity: {t2.get_attribute('class')}")
            t2.click()
            time.sleep(3)
            driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v9_step4_terminal2_clicked.png")
        except Exception as e:
            print(f"Could not find Terminal 2: {e}")
        
        # Try to find any terminal
        terminals = driver.find_elements(By.CSS_SELECTOR, "[class*='terminal']")
        print(f"Found {len(terminals)} terminal elements")
        for i, t in enumerate(terminals):
            print(f"  Terminal {i}: {t.get_attribute('class')}")
        
        print("STEP 5: Check for iframe/terminal interface")
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        print(f"Found {len(iframes)} iframes")
        
        for i, iframe in enumerate(iframes):
            src = iframe.get_attribute("src")
            print(f"Iframe {i}: {src}")
            
            driver.switch_to.frame(iframe)
            driver.save_screenshot(f"/home/claw/.openclaw/workspace/t2_v9_iframe_{i}.png")
            
            # Get all content
            text = driver.find_element(By.TAG_NAME, "body").text
            with open(f"/home/claw/.openclaw/workspace/t2_v9_iframe_{i}.txt", "w") as f:
                f.write(text)
            print(f"Iframe content preview: {text[:1000]}")
            
            # Look for tabs and inputs
            tabs = driver.find_elements(By.CSS_SELECTOR, "[role='tab'], .tab")
            inputs = driver.find_elements(By.TAG_NAME, "input")
            textareas = driver.find_elements(By.TAG_NAME, "textarea")
            
            print(f"  Tabs: {len(tabs)}, Inputs: {len(inputs)}, Textareas: {len(textareas)}")
            
            for tab in tabs:
                print(f"    Tab: '{tab.text}'")
            for inp in inputs:
                print(f"    Input: type={inp.get_attribute('type')} id={inp.get_attribute('id')}")
            
            driver.switch_to.default_content()
        
        print("Done!")
        time.sleep(5)
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_v9_error.png")
    
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
