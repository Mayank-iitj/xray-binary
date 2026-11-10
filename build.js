const fs = require('fs');
const path = require('path');

function copyDir(src, dest) {
  if (!fs.existsSync(dest)) fs.mkdirSync(dest, { recursive: true });
  const entries = fs.readdirSync(src, { withFileTypes: true });
  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

console.log('[build.js] Preparing static frontend distribution...');

// Ensure directories exist
['app', 'dashboard', 'assets', 'public', 'public/app', 'public/dashboard', 'public/assets'].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// 1. Landing page -> root index.html & public/index.html
fs.copyFileSync('apps/web/landing.html', 'index.html');
fs.copyFileSync('apps/web/landing.html', 'public/index.html');
console.log('✓ Root index.html & public/index.html created from landing.html');

// 2. SOC Triage Dashboard -> app/index.html & dashboard/index.html
fs.copyFileSync('apps/web/index.html', 'app/index.html');
fs.copyFileSync('apps/web/index.html', 'public/app/index.html');
fs.copyFileSync('apps/web/index.html', 'dashboard/index.html');
fs.copyFileSync('apps/web/index.html', 'public/dashboard/index.html');
console.log('✓ app/index.html & dashboard/index.html created from apps/web/index.html');

// 3. Static Assets
copyDir('apps/web/assets', 'assets');
copyDir('apps/web/assets', 'public/assets');
console.log('✓ assets/ & public/assets/ synced');

// 4. Favicon
if (fs.existsSync('apps/web/assets/favicon.ico')) {
  fs.copyFileSync('apps/web/assets/favicon.ico', 'favicon.ico');
  fs.copyFileSync('apps/web/assets/favicon.ico', 'public/favicon.ico');
  console.log('✓ favicon.ico copied to root and public');
}

console.log('[build.js] Static frontend distribution ready for Vercel deployment!');
