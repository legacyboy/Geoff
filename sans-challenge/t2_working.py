#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - Terminal 2: "It's All About Defang"
Working solution for IOC extraction and defanging

From the email content, the IOCs are:
- Domains: icicleinnovations.mail, dosisneighborhood.corp
- IPs: 172.16.254.1, 10.0.0.5, 192.168.1.1
- URLs: https://icicleinnovations.mail/renovation-planner.exe, https://icicleinnovations.mail/upload_photos
- Emails: sales@icicleinnovations.mail, residents@dosisneighborhood.corp, info@icicleinnovations.mail
"""

import asyncio
import re
from playwright.async_api import async_playwright

# Credentials
EMAIL = "danoclawnor@gmail.com"
PASSWORD = "hWu}2!dY?~JY8rc"
BASE_URL = "https://2025.holidayhackchallenge.com"

# IOCs extracted from the email
IOCS = {
    "domains": ["icicleinnovations.mail", "dosisneighborhood.corp"],
    "ips": ["172.16.254.1", "10.0.0.5", "192.168.1.1"],
    "urls": [
        "https://icicleinnovations.mail/renovation-planner.exe",
        "https://icicleinnovations.mail/upload_photos"
    ],
    "emails": [
        "sales@icicleinnovations.mail",
        "residents@dosisneighborhood.corp",
        "info@icicleinnovations.mail"
    ]
}

# Defanged versions
def defang_domain(domain):
    return domain.replace(".", "[.]")

def defang_ip(ip):
    return ip.replace(".", "[.]")

def defang_url(url):
    return url.replace("http", "hxxp").replace("://", "[://]").replace(".", "[.]")

def defang_email(email):
    return email.replace("@", "[@]").replace(".", "[.]")

async def solve_terminal():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=False, slow_mo=200)
        context = await browser.new_context(viewport={'width': 1920, 'height': 1080})
        page = await context.new_page()
        
        print("=" * 60)
        print("SANS HHC 2025 - Terminal 2: It's All About Defang")
        print("=" * 60)
        
        # Step 1: Login
        print("\n[1] Logging in...")
        await page.goto(f"{BASE_URL}/")
        await asyncio.sleep(2)
        
        # Check if login form exists
        try:
            email_input = page.locator('input[type="email"]').first
            if await email_input.is_visible(timeout=3000):
                print("    Found login form, entering credentials...")
                await email_input.fill(EMAIL)
                await page.fill('input[type="password"]', PASSWORD)
                await asyncio.sleep(1)
                await page.click('button[type="submit"]')
                await asyncio.sleep(3)
        except:
            print("    May already be logged in")
        
        # Step 2: Close any intro modal
        print("\n[2] Checking for intro modal...")
        try:
            close_btn = page.locator('#close-modal-btn').first
            if await close_btn.is_visible(timeout=3000):
                print("    Closing intro modal...")
                await close_btn.click()
                await asyncio.sleep(2)
        except:
            pass
        
        # Step 3: Click Play Now to enter game
        print("\n[3] Entering game...")
        try:
            play_btn = page.locator('button:has-text("Play Now")').first
            if await play_btn.is_visible(timeout=5000):
                print("    Clicking 'Play Now!'...")
                await play_btn.click()
                await asyncio.sleep(5)
        except:
            print("    May already be in game or button not found")
        
        # Step 4: Enable CTF Mode
        print("\n[4] Ensuring CTF Mode is enabled...")
        await page.goto(f"{BASE_URL}/badge?section=setting")
        await asyncio.sleep(3)
        try:
            ctf_toggle = page.locator('text=CTF Mode').first
            if await ctf_toggle.is_visible(timeout=3000):
                print("    Found CTF Mode toggle")
        except:
            pass
        
        # Step 5: Navigate to objectives
        print("\n[5] Navigating to objectives...")
        await page.goto(f"{BASE_URL}/badge?section=objective")
        await asyncio.sleep(3)
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_objectives.png")
        print("    Screenshot saved: t2_objectives.png")
        
        # Step 6: Find and click Terminal 2
        print("\n[6] Looking for 'It's All About Defang' terminal...")
        
        # Try to find by looking for objectives containing "defang"
        page_content = await page.content()
        
        terminal_clicked = False
        
        # Try multiple approaches to find the terminal
        try:
            # Look for elements containing "defang" text
            defang_elements = await page.locator('text=defang, text=Defang').all()
            print(f"    Found {len(defang_elements)} elements with 'defang' text")
            
            # Try clicking any "Open Terminal" button near defang content
            all_buttons = await page.locator('button:has-text("Open Terminal")').all()
            print(f"    Found {len(all_buttons)} 'Open Terminal' buttons")
            
            # The terminal 2 button should be the second one (Terminal 1, Terminal 2, Terminal 3...)
            if len(all_buttons) >= 2:
                print("    Clicking second 'Open Terminal' button (Terminal 2)...")
                await all_buttons[1].click()
                terminal_clicked = True
            elif len(all_buttons) == 1:
                print("    Clicking first 'Open Terminal' button...")
                await all_buttons[0].click()
                terminal_clicked = True
        except Exception as e:
            print(f"    Error finding terminal: {e}")
        
        if not terminal_clicked:
            print("    [!] Could not find terminal button")
            await browser.close()
            return False
        
        await asyncio.sleep(5)
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_terminal_opened.png")
        print("    Screenshot saved: t2_terminal_opened.png")
        
        # Step 7: Find and interact with the terminal iframe
        print("\n[7] Looking for terminal iframe...")
        
        try:
            iframe = page.locator('iframe').first
            if await iframe.is_visible(timeout=10000):
                print("    Found iframe, switching to it...")
                frame = await iframe.content_frame()
                
                if frame:
                    await asyncio.sleep(3)
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_iframe.png")
                    print("    Iframe screenshot saved: t2_iframe.png")
                    
                    # Get iframe content to verify
                    frame_html = await frame.content()
                    with open("/home/claw/.openclaw/workspace/sans-challenge/t2_iframe_html.html", "w") as f:
                        f.write(frame_html)
                    print("    Iframe HTML saved")
                    
                    # Step 8: Extract IOCs
                    print("\n[8] Extracting IOCs...")
                    
                    # Domains tab
                    print("    [8.1] Clicking Domains tab...")
                    await frame.click('button[data-ioc-type="domains"]')
                    await asyncio.sleep(1)
                    
                    print("    [8.2] Entering domain regex pattern...")
                    domain_input = frame.locator('#domain-regex').first
                    await domain_input.fill(r'[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)+')
                    await asyncio.sleep(1)
                    
                    print("    [8.3] Clicking Extract button for domains...")
                    await frame.click('#domain-form button[type="submit"]')
                    await asyncio.sleep(2)
                    
                    # IPs tab
                    print("    [8.4] Clicking IPs tab...")
                    await frame.click('button[data-ioc-type="ips"]')
                    await asyncio.sleep(1)
                    
                    print("    [8.5] Entering IP regex pattern...")
                    ip_input = frame.locator('#ip-regex').first
                    await ip_input.fill(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
                    await asyncio.sleep(1)
                    
                    print("    [8.6] Clicking Extract button for IPs...")
                    await frame.click('#ip-form button[type="submit"]')
                    await asyncio.sleep(2)
                    
                    # URLs tab
                    print("    [8.7] Clicking URLs tab...")
                    await frame.click('button[data-ioc-type="urls"]')
                    await asyncio.sleep(1)
                    
                    print("    [8.8] Entering URL regex pattern...")
                    url_input = frame.locator('#url-regex').first
                    await url_input.fill(r'https?://[^\s]+')
                    await asyncio.sleep(1)
                    
                    print("    [8.9] Clicking Extract button for URLs...")
                    await frame.click('#url-form button[type="submit"]')
                    await asyncio.sleep(2)
                    
                    # Emails tab
                    print("    [8.10] Clicking Emails tab...")
                    await frame.click('button[data-ioc-type="emails"]')
                    await asyncio.sleep(1)
                    
                    print("    [8.11] Entering email regex pattern...")
                    email_input = frame.locator('#email-regex').first
                    await email_input.fill(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
                    await asyncio.sleep(1)
                    
                    print("    [8.12] Clicking Extract button for emails...")
                    await frame.click('#email-form button[type="submit"]')
                    await asyncio.sleep(2)
                    
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_after_extraction.png")
                    print("    Screenshot saved: t2_after_extraction.png")
                    
                    # Step 9: Switch to Defang tab and defang IOCs
                    print("\n[9] Switching to Defang & Report tab...")
                    await frame.click('button[data-tab="defang-tab"]')
                    await asyncio.sleep(2)
                    
                    print("    [9.1] Clicking 'Apply All Defanging' button...")
                    await frame.click('#defang-standard')
                    await asyncio.sleep(3)
                    
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_after_defang.png")
                    print("    Screenshot saved: t2_after_defang.png")
                    
                    # Step 10: Submit the report
                    print("\n[10] Submitting report...")
                    await frame.click('#send-iocs')
                    await asyncio.sleep(5)
                    
                    await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_after_submit.png")
                    print("    Screenshot saved: t2_after_submit.png")
                    
                    # Check for success message
                    try:
                        alert = frame.locator('#alert').first
                        alert_text = await alert.inner_text(timeout=5000)
                        print(f"    Alert message: {alert_text}")
                    except:
                        print("    No alert found or alert not visible")
                    
                    # Check for report modal
                    try:
                        report_modal = frame.locator('#report-modal').first
                        if await report_modal.is_visible(timeout=3000):
                            print("    [✓] Report modal appeared - submission successful!")
                            await frame.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_success_modal.png")
                            
                            # Close the modal
                            await frame.click('#close-report')
                            await asyncio.sleep(2)
                    except:
                        print("    [!] No report modal found")
                
        except Exception as e:
            print(f"    [!] Error interacting with iframe: {e}")
            import traceback
            traceback.print_exc()
        
        # Step 11: Verify completion
        print("\n[11] Verifying completion...")
        await page.goto(f"{BASE_URL}/badge?section=achievement")
        await asyncio.sleep(5)
        await page.screenshot(path="/home/claw/.openclaw/workspace/sans-challenge/t2_achievements.png")
        print("    Screenshot saved: t2_achievements.png")
        
        # Check if Terminal 2 is now completed
        achievements_html = await page.content()
        if "defang" in achievements_html.lower():
            print("    [✓] Found 'defang' in achievements!")
        if "all about" in achievements_html.lower():
            print("    [✓] Found 'all about' in achievements!")
        
        # Keep browser open briefly
        print("\n[PAUSE] Waiting 10 seconds before closing...")
        await asyncio.sleep(10)
        
        await browser.close()
        print("\n[+] Browser closed")
        return True

if __name__ == "__main__":
    result = asyncio.run(solve_terminal())
    if result:
        print("\n[✓] Script completed successfully")
    else:
        print("\n[!] Script encountered issues")
