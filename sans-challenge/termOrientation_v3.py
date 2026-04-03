#!/usr/bin/env python3
"""
SANS Holiday Hack Challenge 2025 - TermOrientation Challenge Solver V3
Targets the upper challenge input pane specifically
"""

import asyncio
from pyppeteer import launch
import sys

async def solve_term_orientation():
    """Solve termOrientation - target the challenge input, not the shell"""
    
    print("="*60)
    print("SANS HHC 2025 - TermOrientation Solver V3")
    print("="*60 + "\n")
    
    url = "https://hhc25-wetty-prod.holidayhackchallenge.com/?challenge=termOrientation&username=clawdso&id=YTQyNmJiODUtYzY4MC00NTk5LWEyZjYtNTM4MjZmNzdhMDA0&area=train&location=3,4&tokens=&dna=ATATATTAATATATATATATATGCATATATATTATAATATATATATATATATTAGCATATATATATATGCCGATATATATATATATATATATATTAATATATATATATGCCGATATGCTA"
    
    print("[*] Launching browser...")
    
    try:
        browser = await launch(
            headless=False,  # Run visible to see what's happening
            args=['--no-sandbox', '--disable-setuid-sandbox', '--window-size=1280,900']
        )
        
        page = await browser.newPage()
        await page.setViewport({'width': 1280, 'height': 800})
        
        print(f"[*] Navigating to challenge...")
        await page.goto(url, {'waitUntil': 'networkidle2', 'timeout': 30000})
        
        print("[+] Page loaded")
        
        # Wait for terminal to fully initialize
        print("[*] Waiting 10 seconds for terminal...")
        await asyncio.sleep(10)
        
        # Take screenshot to analyze
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_before.png'})
        print("[*] Screenshot saved")
        
        # The challenge input should be at the TOP of the terminal area
        # Based on typical WeTTy layout, try clicking higher up
        # The prompt "Enter the answer here:" should be in the upper portion
        
        print("\n[*] Attempting to find challenge input...")
        
        # Try multiple Y coordinates from top down
        y_positions = [50, 80, 110, 140, 170, 200]  # Various heights in upper area
        x_center = 640  # Center of 1280 width
        
        for y in y_positions:
            print(f"\n[*] Trying click at ({x_center}, {y})...")
            await page.mouse.click(x_center, y)
            await asyncio.sleep(1)
            
            # Type 'answer'
            print(f"  [*] Typing 'answer'...")
            await page.keyboard.type('answer')
            await asyncio.sleep(1)
            
            # Press Enter
            print(f"  [*] Pressing Enter...")
            await page.keyboard.press('Enter')
            await asyncio.sleep(3)
            
            # Check for success
            content = await page.content()
            if any(word in content.lower() for word in ['congratulations', 'correct', 'completed', 'success', 'badge', 'award', 'well done']):
                print(f"  [✓] SUCCESS at Y={y}!")
                await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_success.png'})
                break
            else:
                print(f"  [!] No success at Y={y}")
                
            # Clear any partial input before next try
            await page.keyboard.press('Escape')
            await asyncio.sleep(0.5)
        
        # Also try using JavaScript to directly find and fill the input
        print("\n[*] Trying JavaScript injection...")
        
        # Try to find input by looking for elements near the text "Enter the answer"
        result = await page.evaluate('''() => {
            // Look for elements containing "answer" text or input fields
            const inputs = document.querySelectorAll('input, textarea');
            const results = [];
            for (let input of inputs) {
                const rect = input.getBoundingClientRect();
                results.push({
                    tag: input.tagName,
                    type: input.type,
                    top: rect.top,
                    left: rect.left,
                    width: rect.width,
                    height: rect.height
                });
            }
            return results;
        }''')
        
        print(f"[+] Input elements found via JS:")
        for i, inp in enumerate(result):
            print(f"  Input {i+1}: {inp['tag']} at ({inp['left']:.0f}, {inp['top']:.0f}) size {inp['width']:.0f}x{inp['height']:.0f}")
        
        # Try to fill each input
        for i, inp in enumerate(result):
            if inp['height'] > 10 and inp['width'] > 50:  # Reasonable size for text input
                center_x = inp['left'] + inp['width'] / 2
                center_y = inp['top'] + inp['height'] / 2
                
                print(f"\n[*] Trying input {i+1} at ({center_x:.0f}, {center_y:.0f})...")
                await page.mouse.click(center_x, center_y)
                await asyncio.sleep(1)
                await page.keyboard.type('answer')
                await asyncio.sleep(1)
                await page.keyboard.press('Enter')
                await asyncio.sleep(3)
                
                content = await page.content()
                if any(word in content.lower() for word in ['congratulations', 'correct', 'completed', 'success']):
                    print(f"  [✓] SUCCESS with input {i+1}!")
                    break
        
        # Final check
        await page.screenshot({'path': '/home/claw/.openclaw/workspace/sans-challenge/termOrientation_final.png'})
        
        content = await page.content()
        text = await page.evaluate('() => document.body.innerText')
        
        print("\n[*] Final status check:")
        if 'congratulations' in text.lower():
            print("  [✓] 'Congratulations' found!")
        if 'completed' in text.lower():
            print("  [✓] 'Completed' found!")
        if 'success' in text.lower():
            print("  [✓] 'Success' found!")
        if 'badge' in text.lower():
            print("  [✓] 'Badge' found!")
        if 'award' in text.lower():
            print("  [✓] 'Award' found!")
        
        print(f"\n[*] Final page text preview (first 500 chars):\n{text[:500]}")
        
        await browser.close()
        print("\n[+] Browser closed")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return False
    
    return True

if __name__ == "__main__":
    asyncio.run(solve_term_orientation())
