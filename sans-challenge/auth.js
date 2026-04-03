const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

(async () => {
  console.log('=== SANS Holiday Hack Challenge 2025 - Authentication ===');
  
  const screenshotsDir = '/home/claw/.openclaw/workspace/sans-challenge/screenshots';
  const sessionDir = '/home/claw/.openclaw/workspace/sans-challenge/session';
  
  // Ensure directories exist
  [screenshotsDir, sessionDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });

  const browser = await chromium.launch({ 
    headless: false,
    args: ['--disable-blink-features=AutomationControlled']
  });
  
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
  });
  
  const page = await context.newPage();
  
  // Track console messages
  page.on('console', msg => {
    const type = msg.type();
    const text = msg.text();
    if (type === 'error' || text.includes('error') || text.includes('Error')) {
      console.log(`[PAGE ${type.toUpperCase()}]`, text);
    }
  });
  
  page.on('pageerror', err => console.log('[PAGE ERROR]', err.message));
  
  try {
    // === STEP 1: Navigate to login page ===
    console.log('\n[1/4] Navigating to account.counterhack.com...');
    await page.goto('https://account.counterhack.com?ref=hhc25', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    console.log('Current URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, '01_login_page.png') });
    console.log('Screenshot saved: 01_login_page.png');
    
    await delay(2000);
    
    // === STEP 2: Fill login credentials ===
    console.log('\n[2/4] Filling in credentials...');
    
    // Try multiple selectors for email field
    const emailSelectors = [
      'input[type="email"]',
      'input[name="email"]',
      '#email',
      'input[placeholder*="email" i]',
      'input[id*="email" i]'
    ];
    
    const passwordSelectors = [
      'input[type="password"]',
      'input[name="password"]',
      '#password',
      'input[id*="password" i]'
    ];
    
    let emailFilled = false;
    for (const selector of emailSelectors) {
      try {
        await page.fill(selector, 'danoclawnor@gmail.com');
        console.log('Email filled using selector:', selector);
        emailFilled = true;
        break;
      } catch (e) {}
    }
    
    if (!emailFilled) {
      throw new Error('Could not find email input field');
    }
    
    let passwordFilled = false;
    for (const selector of passwordSelectors) {
      try {
        await page.fill(selector, 'hWu}2!dY?~JY8rc');
        console.log('Password filled using selector:', selector);
        passwordFilled = true;
        break;
      } catch (e) {}
    }
    
    if (!passwordFilled) {
      throw new Error('Could not find password input field');
    }
    
    await delay(1000);
    
    // === STEP 3: Submit login ===
    console.log('\n[3/4] Submitting login form...');
    
    const submitSelectors = [
      'button[type="submit"]',
      'button:has-text("Sign In")',
      'button:has-text("Login")',
      'button:has-text("Log in")',
      'input[type="submit"]',
      'button:has-text("Submit")'
    ];
    
    let submitted = false;
    for (const selector of submitSelectors) {
      try {
        await Promise.all([
          page.waitForNavigation({ timeout: 15000 }).catch(() => {}),
          page.click(selector)
        ]);
        console.log('Clicked submit using selector:', selector);
        submitted = true;
        break;
      } catch (e) {}
    }
    
    if (!submitted) {
      // Try pressing Enter
      await page.keyboard.press('Enter');
      await delay(3000);
    }
    
    await delay(3000);
    console.log('URL after login attempt:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, '02_after_login.png') });
    console.log('Screenshot saved: 02_after_login.png');
    
    // === STEP 4: Navigate to game ===
    console.log('\n[4/4] Navigating to Holiday Hack Challenge...');
    await page.goto('https://2025.holidayhackchallenge.com/', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    await delay(3000);
    console.log('Current URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, '03_game_loaded.png') });
    console.log('Screenshot saved: 03_game_loaded.png');
    
    // Check if we're logged in
    const pageContent = await page.content();
    const isLoggedIn = pageContent.includes('logout') || 
                       pageContent.includes('Log Out') || 
                       pageContent.includes('danoclawnor') ||
                       !pageContent.includes('Sign In');
    
    console.log('\n=== LOGIN STATUS ===');
    if (isLoggedIn) {
      console.log('✅ Successfully logged in to Holiday Hack Challenge!');
    } else {
      console.log('⚠️ Login status unclear. Please check the screenshots.');
    }
    
    // Save session data
    const cookies = await context.cookies();
    fs.writeFileSync(path.join(sessionDir, 'cookies.json'), JSON.stringify(cookies, null, 2));
    console.log('\nSession cookies saved to session/cookies.json');
    
    // Get localStorage
    const localStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        items[key] = localStorage.getItem(key);
      }
      return items;
    });
    fs.writeFileSync(path.join(sessionDir, 'localStorage.json'), JSON.stringify(localStorage, null, 2));
    console.log('LocalStorage saved to session/localStorage.json');
    
    // Wait for user to explore
    console.log('\n=== Browser will remain open for 60 seconds ===');
    console.log('Use this time to explore the challenge map.');
    console.log('Close the browser manually when done.');
    
    await delay(60000);
    
  } catch (error) {
    console.error('\n❌ ERROR:', error.message);
    try {
      await page.screenshot({ path: path.join(screenshotsDir, 'error_screenshot.png') });
      console.log('Error screenshot saved');
    } catch (e) {}
  } finally {
    await browser.close();
    console.log('\nBrowser closed.');
  }
})();
