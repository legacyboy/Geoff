#!/usr/bin/env python3
"""
SANS HHC 2025 - Terminal 1 - Proper xterm input
"""

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.action_chains import ActionChains
import time
import os

EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"


def solve():
    print("=" * 60)
    print("SANS HHC 2025 - Terminal 1 - xterm Input")
    print("=" * 60 + "\n")

    options = Options()
    options.add_argument("--width=1400")
    options.add_argument("--height=900")
    os.environ['DISPLAY'] = ':0'

    driver = webdriver.Firefox(options=options)

    try:
        # Login
        print("[*] Logging in...")
        driver.get("https://account.counterhack.com?ref=hhc25")
        time.sleep(2)
        driver.find_element(By.CSS_SELECTOR, "input[type='email']").send_keys(EMAIL)
        driver.find_element(By.CSS_SELECTOR, "input[type='password']").send_keys(PASSWORD + Keys.RETURN)
        time.sleep(5)
        print("[+] Logged in\n")

        # Enter game
        print("[*] Entering game...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Play Now')]").click()
        time.sleep(20)

        # CTF Mode
        driver.get("https://2025.holidayhackchallenge.com/badge?section=setting")
        time.sleep(5)
        try:
            driver.find_element(By.XPATH, "//*[contains(text(), 'CTF Style')]").click()
            time.sleep(3)
        except:
            pass

        # Objectives
        driver.get("https://2025.holidayhackchallenge.com/badge?section=objective")
        time.sleep(15)

        # Click terminal
        print("[*] Clicking terminal...")
        driver.find_element(By.XPATH, "//button[contains(text(), 'Open Terminal')]").click()
        time.sleep(40)  # Wait for terminal to fully load

        # Switch to iframe
        iframes = driver.find_elements(By.TAG_NAME, "iframe")
        if iframes:
            driver.switch_to.frame(iframes[0])
            print("[+] Switched to iframe")
        
        # Wait for terminal
        time.sleep(10)
        
        # Method 1: Click on xterm canvas and use Actions
        print("\n[*] Method 1: Click canvas + Actions...")
        try:
            canvas = driver.find_element(By.CSS_SELECTOR, ".xterm-screen")
            canvas.click()
            time.sleep(2)
            
            # Use ActionChains to type
            actions = ActionChains(driver)
            actions.send_keys("answer")
            actions.perform()
            time.sleep(1)
            
            actions = ActionChains(driver)
            actions.send_keys(Keys.RETURN)
            actions.perform()
            time.sleep(5)
            
            print("[+] Method 1 done")
        except Exception as e:
            print(f"[!] Method 1 failed: {e}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_method1.png")
        
        # Method 2: JavaScript to trigger xterm input
        print("\n[*] Method 2: JavaScript xterm input...")
        try:
            driver.execute_script("""
                // Try to access xterm and send input
                if (window.term && window.term._core) {
                    // Get the terminal's input handler
                    var core = window.term._core;
                    
                    // Send each character
                    var text = 'answer';
                    for (var i = 0; i < text.length; i++) {
                        var charCode = text.charCodeAt(i);
                        // Simulate key down
                        var event = new KeyboardEvent('keydown', {
                            key: text[i],
                            code: 'Key' + text[i].toUpperCase(),
                            charCode: charCode,
                            keyCode: charCode,
                            which: charCode,
                            bubbles: true
                        });
                        document.dispatchEvent(event);
                        
                        // Simulate key press
                        event = new KeyboardEvent('keypress', {
                            key: text[i],
                            charCode: charCode,
                            keyCode: charCode,
                            which: charCode,
                            bubbles: true
                        });
                        document.dispatchEvent(event);
                        
                        // Simulate input
                        event = new InputEvent('input', {
                            data: text[i],
                            inputType: 'insertText',
                            bubbles: true
                        });
                        document.dispatchEvent(event);
                        
                        // Simulate key up
                        event = new KeyboardEvent('keyup', {
                            key: text[i],
                            code: 'Key' + text[i].toUpperCase(),
                            charCode: charCode,
                            keyCode: charCode,
                            which: charCode,
                            bubbles: true
                        });
                        document.dispatchEvent(event);
                    }
                    
                    // Send Enter
                    var enterEvent = new KeyboardEvent('keydown', {
                        key: 'Enter',
                        code: 'Enter',
                        keyCode: 13,
                        which: 13,
                        bubbles: true
                    });
                    document.dispatchEvent(enterEvent);
                    
                    enterEvent = new KeyboardEvent('keyup', {
                        key: 'Enter',
                        code: 'Enter',
                        keyCode: 13,
                        which: 13,
                        bubbles: true
                    });
                    document.dispatchEvent(enterEvent);
                    
                    return 'Input sent via JS events';
                }
                return 'window.term not found';
            """)
            time.sleep(5)
            print("[+] Method 2 done")
        except Exception as e:
            print(f"[!] Method 2 failed: {e}")
        
        # Screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_method2.png")
        
        # Method 3: Direct websocket/socket.io communication
        print("\n[*] Method 3: Socket emit...")
        try:
            driver.execute_script("""
                // Try to emit via socket
                if (window.socket) {
                    window.socket.emit('input', 'answer\r');
                    return 'Emitted via socket';
                }
                // Try conduit
                if (window.conduit) {
                    window.conduit.emit('input', 'answer\r');
                    return 'Emitted via conduit';
                }
                // Try term socket
                if (window.term && window.term.socket) {
                    window.term.socket.emit('input', 'answer\r');
                    return 'Emitted via term.socket';
                }
                return 'No socket found';
            """)
            time.sleep(5)
            print("[+] Method 3 done")
        except Exception as e:
            print(f"[!] Method 3 failed: {e}")
        
        # Final screenshot
        driver.save_screenshot("/home/claw/.openclaw/workspace/sans-challenge/t1_final.png")
        
        # Switch back and check
        driver.switch_to.default_content()
        print("\n[*] Checking completion...")
        
        time.sleep(3)
        text = driver.find_element(By.TAG_NAME, "body").text
        if any(k in text.lower() for k in ['completed', 'correct', '2']):
            print("[✓] Challenge may be complete!")

    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

    finally:
        driver.quit()
        print("\n[+] Done")


if __name__ == "__main__":
    solve()
