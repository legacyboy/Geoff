const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');

async function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

(async () => {
  console.log('=== SANS Holiday Hack Challenge 2025 - Authentication v2 ===');
  
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
    // Step 1: Login to account portal
    console.log('\n[1/5] Logging in to account.counterhack.com...');
    await page.goto('https://account.counterhack.com?ref=hhc25', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    await page.fill('input[type="email"]', 'danoclawnor@gmail.com');
    await page.fill('input[type="password"]', 'hWu}2!dY?~JY8rc');
    await page.click('button[type="submit"]');
    
    await delay(3000);
    console.log('Logged in. Current URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, 'v2_01_logged_in.png') });
    
    // Step 2: Look for game access link/button
    console.log('\n[2/5] Looking for game access...');
    const pageText = await page.content();
    
    // Save page content for analysis
    fs.writeFileSync(path.join(sessionDir, 'account_page.html'), pageText);
    console.log('Page content saved to session/account_page.html');
    
    // Check for any links to the game
    const links = await page.$$eval('a', anchors => 
      anchors.map(a => ({ href: a.href, text: a.textContent.trim() }))
    );
    console.log('Found links:', links.filter(l => l.href.includes('hhc') || l.href.includes('holiday') || l.href.includes('game')));
    
    // Step 3: Try to access the game directly with session
    console.log('\n[3/5] Accessing Holiday Hack Challenge game...');
    await page.goto('https://2025.holidayhackchallenge.com/', { 
      waitUntil: 'networkidle',
      timeout: 60000 
    });
    
    await delay(5000);
    console.log('Game URL:', page.url());
    await page.screenshot({ path: path.join(screenshotsDir, 'v2_02_game_page.png') });
    
    // Step 4: Wait for game to fully load and take screenshot
    console.log('\n[4/5] Waiting for game to initialize...');
    await delay(10000);
    await page.screenshot({ path: path.join(screenshotsDir, 'v2_03_game_loaded.png'), fullPage: true });
    
    // Step 5: Save all cookies and storage
    const cookies = await context.cookies();
    fs.writeFileSync(path.join(sessionDir, 'cookies_v2.json'), JSON.stringify(cookies, null, 2));
    
    const localStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        items[key] = localStorage.getItem(key);
      }
      return items;
    });
    fs.writeFileSync(path.join(sessionDir, 'localStorage_v2.json'), JSON.stringify(localStorage, null, 2));
    
    const sessionStorage = await page.evaluate(() => {
      const items = {};
      for (let i = 0; i < sessionStorage.length; i++) {
        const key = sessionStorage.key(i);
        items[key] = sessionStorage.getItem(key);
      }
      return items;
    });
    fs.writeFileSync(path.join(sessionDir, 'sessionStorage_v2.json'), JSON.stringify(sessionStorage, null, 2));
    
    console.log('\n[5/5] Session saved successfully!');
    console.log('Cookies saved:', cookies.length);
    console.log('localStorage keys:', Object.keys(localStorage).length);
    console.log('sessionStorage keys:', Object.keys(sessionStorage).length);
    
    // Print page info
    const finalContent = await page.content();
    const title = await page.title();
    console.log('\nPage Title:', title);
    console.log('Page URL:', page.url());
    
    // Check if we're in the game
    if (finalContent.includes('Holiday Hack') || finalContent.includes('challenge') || finalContent.includes(' elf ')) {
      console.log('\n✅ Successfully loaded Holiday Hack Challenge!');
    } else {
      console.log('\n⚠️ May need additional steps. Check screenshots.');
    }
    
    // Save final page HTML
    fs.writeFileSync(path.join(sessionDir, 'game_page.html'), finalContent);
    
    // Keep browser open
    console.log('\n=== Browser open for 60 seconds to explore ===');
    await delay(60000);
    
  } catch (error) {
    console.error('\n❌ ERROR:', error.message);
    await page.screenshot({ path: path.join(screenshotsDir, 'v2_error.png') });
  } finally {
    await browser.close();
    console.log('\nBrowser closed.');
  }
})();
