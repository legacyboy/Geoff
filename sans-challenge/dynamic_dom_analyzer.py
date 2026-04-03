#!/usr/bin/env python3
"""
SANS HHC 2025 - Dynamic DOM Analyzer
Uses Selenium to render JavaScript and inspect the actual challenge UI
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.options import Options
import time
import os
import json

def analyze():
    print("=" * 80)
    print("SANS HHC 2025 - Dynamic DOM Analyzer")
    print("=" * 80 + "\n")
    
    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'
    
    driver = webdriver.Firefox(options=options)
    
    try:
        # Load terminal URL
        url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
        
        print(f"[*] Loading: {url[:80]}...")
        driver.get(url)
        time.sleep(15)  # Wait for JavaScript to render
        
        print("[+] Page loaded\n")
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/dom_analysis.png")
        
        # Analyze all interactive elements
        results = {
            "url": driver.current_url,
            "title": driver.title,
            "inputs": [],
            "textareas": [],
            "contenteditables": [],
            "buttons": [],
            "divs_with_click": [],
            "challenge_elements": []
        }
        
        # Find all input elements
        print("=" * 80)
        print("INPUT ELEMENTS")
        print("=" * 80)
        inputs = driver.find_elements(By.TAG_NAME, "input")
        print(f"[*] Found {len(inputs)} input elements\n")
        
        for i, inp in enumerate(inputs):
            try:
                info = {
                    "index": i,
                    "type": inp.get_attribute("type"),
                    "id": inp.get_attribute("id"),
                    "class": inp.get_attribute("class"),
                    "placeholder": inp.get_attribute("placeholder"),
                    "name": inp.get_attribute("name"),
                    "visible": inp.is_displayed(),
                    "location": inp.location,
                    "size": inp.size
                }
                results["inputs"].append(info)
                print(f"[Input {i}] type={info['type']}, id={info['id']}, class={info['class']}")
                print(f"          placeholder={info['placeholder']}, visible={info['visible']}")
                print(f"          location={info['location']}, size={info['size']}\n")
            except Exception as e:
                print(f"[!] Error on input {i}: {e}")
        
        # Find all textareas
        print("=" * 80)
        print("TEXTAREA ELEMENTS")
        print("=" * 80)
        textareas = driver.find_elements(By.TAG_NAME, "textarea")
        print(f"[*] Found {len(textareas)} textarea elements\n")
        
        for i, ta in enumerate(textareas):
            try:
                info = {
                    "index": i,
                    "id": ta.get_attribute("id"),
                    "class": ta.get_attribute("class"),
                    "visible": ta.is_displayed(),
                    "location": ta.location,
                    "size": ta.size
                }
                results["textareas"].append(info)
                print(f"[Textarea {i}] id={info['id']}, class={info['class']}")
                print(f"             visible={info['visible']}, location={info['location']}\n")
            except Exception as e:
                print(f"[!] Error on textarea {i}: {e}")
        
        # Find contenteditable elements
        print("=" * 80)
        print("CONTENTEDITABLE ELEMENTS")
        print("=" * 80)
        editables = driver.find_elements(By.CSS_SELECTOR, "[contenteditable='true']")
        print(f"[*] Found {len(editables)} contenteditable elements\n")
        
        for i, elem in enumerate(editables):
            try:
                info = {
                    "index": i,
                    "tag": elem.tag_name,
                    "id": elem.get_attribute("id"),
                    "class": elem.get_attribute("class"),
                    "visible": elem.is_displayed(),
                    "location": elem.location,
                    "size": elem.size
                }
                results["contenteditables"].append(info)
                print(f"[Editable {i}] tag={info['tag']}, id={info['id']}")
                print(f"            class={info['class']}, visible={info['visible']}\n")
            except Exception as e:
                print(f"[!] Error on editable {i}: {e}")
        
        # Find all buttons
        print("=" * 80)
        print("BUTTON ELEMENTS")
        print("=" * 80)
        buttons = driver.find_elements(By.TAG_NAME, "button")
        print(f"[*] Found {len(buttons)} button elements\n")
        
        for i, btn in enumerate(buttons):
            try:
                info = {
                    "index": i,
                    "id": btn.get_attribute("id"),
                    "class": btn.get_attribute("class"),
                    "text": btn.text[:50] if btn.text else "",
                    "visible": btn.is_displayed(),
                    "location": btn.location
                }
                results["buttons"].append(info)
                if info["text"]:
                    print(f"[Button {i}] text='{info['text']}', class={info['class']}")
            except Exception as e:
                print(f"[!] Error on button {i}: {e}")
        
        # Look for challenge-specific elements
        print("\n" + "=" * 80)
        print("CHALLENGE-SPECIFIC ELEMENTS")
        print("=" * 80)
        
        # Try various selectors
        selectors = [
            "[data-testid]",
            "[data-challenge]",
            "[data-answer]",
            ".challenge",
            ".challenge-input",
            ".answer-input",
            "[placeholder*='answer']",
            "[placeholder*='Answer']"
        ]
        
        for selector in selectors:
            try:
                elems = driver.find_elements(By.CSS_SELECTOR, selector)
                if elems:
                    print(f"\n[Selector: {selector}] Found {len(elems)} elements")
                    for elem in elems:
                        print(f"  - tag={elem.tag_name}, id={elem.get_attribute('id')}, class={elem.get_attribute('class')}")
            except Exception as e:
                pass
        
        # Try to find elements by text content
        print("\n" + "=" * 80)
        print("ELEMENTS BY TEXT CONTENT")
        print("=" * 80)
        
        body_text = driver.find_element(By.TAG_NAME, "body").text
        print(f"Body text preview:\n{body_text[:500]}...")
        
        # Look for specific keywords
        keywords = ["answer", "Answer", "submit", "Submit", "challenge", "Challenge"]
        print("\n[*] Searching for keywords:", keywords)
        
        for keyword in keywords:
            try:
                xpath = f"//*[contains(text(), '{keyword}')]"
                elems = driver.find_elements(By.XPATH, xpath)
                if elems:
                    print(f"\n  Found {len(elems)} elements with '{keyword}':")
                    for elem in elems[:5]:  # Limit to first 5
                        try:
                            print(f"    - {elem.tag_name}: {elem.text[:50]}")
                        except:
                            pass
            except:
                pass
        
        # Save results
        with open("/home/claw/.openclaw/workspace/sans-challenge/dom_analysis.json", "w") as f:
            json.dump(results, f, indent=2)
        print("\n[+] Results saved to dom_analysis.json")
        print("[+] Screenshot saved to dom_analysis.png")
        
        print("\n" + "=" * 80)
        print("ANALYSIS COMPLETE")
        print("=" * 80)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        input("\nPress Enter to close browser...")
        driver.quit()

if __name__ == "__main__":
    analyze()
