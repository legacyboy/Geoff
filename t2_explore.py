#!/usr/bin/env python3
"""Explore the HHC website structure first"""

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
        print("Loading main page...")
        driver.get("https://2025.holidayhackchallenge.com/")
        time.sleep(3)
        
        # Save screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/t2_explore_main.png")
        
        # Get all links
        links = driver.find_elements(By.TAG_NAME, "a")
        print(f"\nFound {len(links)} links:")
        for link in links:
            text = link.text.strip()
            href = link.get_attribute("href")
            if text:
                print(f"  - '{text}' -> {href}")
        
        # Get all buttons
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"\nFound {len(buttons)} buttons:")
        for btn in buttons:
            text = btn.text.strip()
            if text:
                print(f"  - '{text}'")
        
        # Get page title
        print(f"\nPage title: {driver.title}")
        
        # Check if already logged in
        page_source = driver.page_source.lower()
        if "logout" in page_source or "sign out" in page_source:
            print("\nAlready logged in!")
        else:
            print("\nNeed to log in")
        
        # Save HTML for inspection
        with open("/home/claw/.openclaw/workspace/t2_explore_main.html", "w") as f:
            f.write(driver.page_source)
        
        print("\nSaved screenshot and HTML. Check t2_explore_main.png and t2_explore_main.html")
        
        time.sleep(5)
        
    finally:
        driver.quit()

if __name__ == "__main__":
    main()
