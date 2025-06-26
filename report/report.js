// --- Dark Mode toggle ---
if (localStorage.getItem('report-dark-mode') === '1') {
  document.body.classList.add('dark');
}
function updateDarkIcon() {
  let icon = document.getElementById('toggle-dark-icon');
  if (icon) icon.textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
}
document.addEventListener('DOMContentLoaded', function() {
  updateDarkIcon();
  var darkBtn = document.getElementById('toggle-dark');
  if (darkBtn) {
    darkBtn.addEventListener('click', function(e) {
      e.preventDefault();
      const isDark = document.body.classList.toggle('dark');
      localStorage.setItem('report-dark-mode', isDark ? '1' : '0');
      updateDarkIcon();
    });
  }
  setupReport();
});

// --- Utility: Copy to clipboard ---
function copySection(targetId) {
  const el = document.getElementById(targetId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => {
    // Optionally, give feedback (alert or flash)
  });
}

// --- Utility: Toggle collapsible section ---
function toggleSection(targetId) {
  const el = document.getElementById(targetId);
  if (!el) return;
  el.style.display = (el.style.display === 'none' || !el.style.display) ? 'block' : 'none';
}

// --- Screenshot Lightbox ---
function showLightbox(src, alt) {
  let lb = document.createElement('div');
  lb.id = 'lightbox';
  lb.style.cssText = 'position:fixed;inset:0;z-index:9999;background:#000d;background:rgba(0,0,0,0.9);display:flex;align-items:center;justify-content:center;';
  lb.innerHTML = `<img src="${src}" alt="${alt}" style="max-width:90vw;max-height:90vh;border:4px solid #fff;border-radius:8px;">
    <span style="position:absolute;top:20px;right:40px;font-size:2rem;color:#fff;cursor:pointer;" id="close-lightbox">&times;</span>`;
  document.body.appendChild(lb);
  lb.addEventListener('click', function(e) {
    if (e.target === lb || e.target.id === 'close-lightbox') lb.remove();
  });
}

// --- Main setup ---
function setupReport() {
  const d = window.reportData || {};

  // Show/Hide handlers
  document.querySelectorAll('.toggle-section').forEach(btn => {
    btn.addEventListener('click', () => toggleSection(btn.dataset.target));
  });

  // Copy handlers
  document.querySelectorAll('.copy-section').forEach(btn => {
    btn.addEventListener('click', () => copySection(btn.dataset.target));
  });

  // Stats
  if (d.stats) {
    if (document.getElementById('stat-subdomains')) document.getElementById('stat-subdomains').textContent = d.stats.subdomains;
    if (document.getElementById('stat-alive')) document.getElementById('stat-alive').textContent = d.stats.alive;
    if (document.getElementById('stat-alive-web')) document.getElementById('stat-alive-web').textContent = d.stats.aliveWeb;
    if (document.getElementById('stat-urls')) document.getElementById('stat-urls').textContent = d.stats.urls;
    if (document.getElementById('stat-new-subs')) document.getElementById('stat-new-subs').textContent = d.stats.newSubs;
  }
  // Tool versions
  if (d.toolVersions && document.getElementById('tool-versions'))
    document.getElementById('tool-versions').textContent = d.toolVersions;
  // New subdomains
  if (d.newSubdomains && document.getElementById('new-subdomains-pre'))
    document.getElementById('new-subdomains-pre').textContent = d.newSubdomains;
  // Endpoints
  if (d.endpoints && document.getElementById('endpoints-pre'))
    document.getElementById('endpoints-pre').textContent = d.endpoints;
  // Parameters
  if (d.parameters && document.getElementById('parameters-pre'))
    document.getElementById('parameters-pre').textContent = d.parameters;
  // Vulnerabilities
  if (d.vulnerabilities) {
    if (d.vulnerabilities.nuclei && document.getElementById('vuln-nuclei'))
      document.getElementById('vuln-nuclei').textContent = d.vulnerabilities.nuclei;
    if (d.vulnerabilities.dalfox && document.getElementById('vuln-dalfox'))
      document.getElementById('vuln-dalfox').textContent = d.vulnerabilities.dalfox;
    if (d.vulnerabilities.kxss && document.getElementById('vuln-kxss'))
      document.getElementById('vuln-kxss').textContent = d.vulnerabilities.kxss;
  }
  // Screenshots with lightbox
  if (d.screenshots && document.getElementById('screenshots-grid')) {
    let grid = document.getElementById('screenshots-grid');
    d.screenshots.forEach(function(s) {
      let img = document.createElement('img');
      img.src = s.file;
      img.alt = s.label || s.file;
      img.tabIndex = 0;
      img.style = "max-width:150px;max-height:150px;cursor:pointer;margin:5px;border-radius:4px;";
      img.addEventListener('click', () => showLightbox(img.src, img.alt));
      img.addEventListener('keypress', e => { if (e.key === 'Enter') showLightbox(img.src, img.alt); });
      grid.appendChild(img);
    });
  }
  // Chart.js summary
  if (window.Chart && document.getElementById('summaryChart') && d.stats) {
    let ctx = document.getElementById('summaryChart').getContext('2d');
    new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Subdomains', 'Alive', 'Alive web', 'URLs', 'New subs'],
        datasets: [{
          data: [
            d.stats?.subdomains || 0,
            d.stats?.alive || 0,
            d.stats?.aliveWeb || 0,
            d.stats?.urls || 0,
            d.stats?.newSubs || 0
          ],
          backgroundColor: [
            '#5fa1f7', '#254a7d', '#fbc02d', '#388e3c', '#e53935'
          ]
        }]
      },
      options: {
        responsive: true,
        plugins: { legend: { position: 'bottom' } }
      }
    });
  }
}
