#!/usr/bin/env python3
"""
SANS HHC 2025 - TermOrientation Solver
Targeted approach to find and fill the challenge input
"""

import asyncio
from pyppeteer import launch

async def solve():
    print("="*60)
    print("SANS HHC 2025 - TermOrientation")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    browser = await launch(headless=True, args=['--no-sandbox'])
    page = await browser.newPage()
    await page.setViewport({'width': 1280, 'height': 800})
    
    await page.goto(url, {'waitUntil': 'networkidle2'})
    await asyncio.sleep(8)
    
    print("[+] Terminal loaded")
    
    # Get full page HTML to understand structure
    html = await page.content()
    
    # Look for the challenge input - it's often a separate div or input
    # Try to find it by searching for "answer" in the HTML
    if 'answer' in html.lower():
        print("[+] 'answer' found in page HTML")
    
    # The challenge might use a different mechanism
    # Let's try executing JavaScript to find all interactive elements
    elements = await page.evaluate('''() => {
        const allElements = document.querySelectorAll('*');
        const interactive = [];
        for (const el of allElements) {
            if (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.contentEditable === 'true') {
                const rect = el.getBoundingClientRect();
                interactive.push({
                    tag: el.tagName,
                    id: el.id,
                    class: el.className,
                    type: el.type,
                    top: rect.top,
                    left: rect.left,
                    width: rect.width,
                    height: rect.height
                });
            }
        }
        return interactive;
    }''')
    
    print(f"\n[+] Found {len(elements)} interactive elements:")
    for i, el in enumerate(elements):
        print(f"  {i+1}. {el['tag']}#{el['id']} at ({el['left']:.0f}, {el['top']:.0f}) {el['width']:.0f}x{el['height']:.0f}")
    
    # Try each input element
    for el in elements:
        if el['height'] < 20 or el['width'] < 100:
            continue  # Skip tiny elements
            
        try:
            selector = el['id'] and f"#{el['id']}" or f".{el['class'].split(' ')[0]}"
            element = await page.querySelector(selector)
            if element:
                print(f"\n[*] Trying element: {selector}")
                await element.click()
                await asyncio.sleep(0.5)
                await element.type('answer')
                await asyncio.sleep(0.5)
                await page.keyboard.press('Enter')
                await asyncio.sleep(3)
                
                # Check for success
                text = await page.evaluate('() => document.body.innerText')
                if any(word in text.lower() for word in ['congratulations', 'completed', 'success', 'correct']):
                    print("[✓] SUCCESS!")
                    break
        except Exception as e:
            print(f"  [!] Error: {e}")
    
    await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_result.png'})
    print("\n[+] Screenshot saved")
    
    await browser.close()

if __name__ == "__main__":
    asyncio.run(solve())
