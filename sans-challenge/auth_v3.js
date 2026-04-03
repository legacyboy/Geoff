const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

(async () => {
  console.log('=== SANS Holiday Hack Challenge 2025 - Authentication v3 ===');
  
  const screenshotsDir = '/home/claw/.openclaw/workspace/sans-challenge/screenshots';
  const sessionDir = '/home/claw/.openclaw/workspace/sans-challenge/session';
  
  [screenshotsDir, sessionDir].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  });

  const browser = await chromium.launch({ 
    headless: false,
    args: ['--disable-blink-features=AutomationControlled']
  });
  
  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    userAgent: 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
  });
  
  const page = await context.newPage();
  
  try {
    // Step 1: Navigate to login page
    console.log('\n[1/6] Navigating to login page...');
    await page.goto('https://account.counterhack.com?ref=hhc25', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    await delay(2000);
    await page.screenshot({ path: path.join(screenshotsDir, 'v3_01_login.png') });
    console.log('Screenshot: v3_01_login.png');
    
    // Step 2: Fill in credentials
    console.log('\n[2/6] Filling credentials...');
    await page.fill('input[name="email"]', 'danoclawnor@gmail.com');
    await page.fill('input[name="password"]', 'hWu}2!dY?~JY8rc');
    
    // Step 3: Submit form using traditional POST (not HTMX)
    // Intercept the form submission and do a full navigation
    console.log('\n[3/6] Submitting login form...');
    
    // Remove HTMX attributes and submit traditionally
    await page.evaluate(() => {
      const form = document.querySelector('form');
      if (form) {
        form.removeAttribute('hx-post');
        form.removeAttribute('hx-target');
        form.removeAttribute('hx-swap');
        form.setAttribute('action', '/login');
        form.setAttribute('method', 'post');
      }
    });
    
    // Now submit
    await Promise.all([
      page.waitForNavigation({ timeout: 15000 }).catch(() => {}),
      page.click('button[type="submit"]')
    ]);
    
    await delay(3000);
    console.log('After login URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, 'v3_02_after_login.png') });
    console.log('Screenshot: v3_02_after_login.png');
    
    // Step 4: Check if we're logged in - look for dashboard content
    const content = await page.content();
    fs.writeFileSync(path.join(sessionDir, 'after_login.html'), content);
    
    // Step 5: Access the Holiday Hack Challenge game
    console.log('\n[4/6] Accessing Holiday Hack Challenge...');
    await page.goto('https://2025.holidayhackchallenge.com/', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    await delay(5000);
    console.log('Game page URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, 'v3_03_game.png') });
    console.log('Screenshot: v3_03_game.png');
    
    // Step 6: Wait for game to load fully
    console.log('\n[5/6] Waiting for game initialization...');
    await delay(10000);
    await page.screenshot({ path: path.join(screenshotsDir, 'v3_04_game_full.png'), fullPage: true });
    console.log('Screenshot: v3_04_game_full.png');
    
    // Save page content for analysis
    const gameContent = await page.content();
    fs.writeFileSync(path.join(sessionDir, 'game_page.html'), gameContent);
    
    // Look for game elements
    const hasGame = gameContent.includes('elf') || 
                    gameContent.includes('challenge') || 
                    gameContent.includes('map') ||
                    gameContent.includes('HHC') ||
                    gameContent.includes('Santa');
    
    console.log('\n[6/6] Saving session data...');
    const cookies = await context.cookies();
    fs.writeFileSync(path.join(sessionDir, 'cookies.json'), JSON.stringify(cookies, null, 2));
    
    const localStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        items[key] = localStorage.getItem(key);
      }
      return items;
    });
    fs.writeFileSync(path.join(sessionDir, 'localStorage.json'), JSON.stringify(localStorage, null, 2));
    
    console.log('\n=== RESULTS ===');
    console.log('Current URL:', page.url());
    console.log('Cookies:', cookies.length);
    console.log('localStorage keys:', Object.keys(localStorage).length);
    
    if (hasGame) {
      console.log('\n✅ Holiday Hack Challenge appears to be loaded!');
    } else {
      console.log('\n⚠️ Game status unclear. Check screenshots and saved HTML.');
    }
    
    // Keep browser open
    console.log('\n=== Browser open for 90 seconds ===');
    await delay(90000);
    
  } catch (error) {
    console.error('\n❌ ERROR:', error.message);
    await page.screenshot({ path: path.join(screenshotsDir, 'v3_error.png') });
  } finally {
    await browser.close();
    console.log('\nBrowser closed.');
  }
})();
