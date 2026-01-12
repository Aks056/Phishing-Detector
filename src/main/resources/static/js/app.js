document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('checkForm');
  const urlInput = document.getElementById('url_input');
  const checkBtn = document.getElementById('checkBtn');
  const clearBtn = document.getElementById('clearBtn');
  const resultSection = document.getElementById('result');
  const loaderSection = document.getElementById('loader');
  const verdictEl = document.getElementById('verdict');
  const reasonsList = document.getElementById('reasonsList');
  const checkedUrl = document.getElementById('checkedUrl');
  const scoreBadge = document.getElementById('scoreBadge');
  const riskLevelEl = document.getElementById('riskLevel');
  const rawResponse = document.getElementById('rawResponse');

  // Hide loader after initialization
  setTimeout(() => {
    loaderSection.classList.remove('show');
  }, 2000);

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    resultSection.classList.remove('show');
    loaderSection.classList.remove('show');
  });

  const historyListEl = document.getElementById('historyList');
  const historySection = document.getElementById('history');
  const clearHistoryBtn = document.getElementById('clearHistory');

  // Helper: read/write history (max 10 entries)
  function loadHistory() {
    try {
      const raw = localStorage.getItem('phishing_history');
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }
  function saveHistory(arr) {
    localStorage.setItem('phishing_history', JSON.stringify(arr.slice(0,10)));
  }
  function renderHistory() {
    const items = loadHistory();
    historyListEl.innerHTML = '';
    if (!items.length) {
      historySection.classList.remove('show');
      return;
    }
    historySection.classList.add('show');
    items.forEach(it => {
      const li = document.createElement('li');
      li.className = it.isPhishing ? 'danger' : 'safe';
      li.textContent = `${new Date(it.ts).toLocaleString()} — ${it.url} — ${it.riskLevel} (${it.riskScore})`;
      li.addEventListener('click', () => {
        urlInput.value = it.url;
        // re-run analysis quickly
        form.dispatchEvent(new Event('submit', { cancelable: true }));
      });
      historyListEl.appendChild(li);
    });
  }

  clearHistoryBtn.addEventListener('click', () => {
    localStorage.removeItem('phishing_history');
    renderHistory();
  });

  renderHistory();

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    checkBtn.disabled = true;
    checkBtn.textContent = 'Analyzing...';

    // Show loader during analysis
    loaderSection.classList.add('show');
    resultSection.classList.remove('show');

    try {
      const resp = await fetch('/api/v1/phishing/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!resp.ok) {
        throw new Error('Server error: ' + resp.status);
      }

      const data = await resp.json();

      // Response mapping: match UrlCheckResponse DTO fields
      const isPhishing = data.isPhishing === true;
      const score = typeof data.riskScore === 'number' ? data.riskScore : 0;
      const level = data.riskLevel || (score > 50 ? 'HIGH' : (score > 20 ? 'MEDIUM' : 'LOW'));
      const reasons = Array.isArray(data.detectedThreats) ? data.detectedThreats : [];
      const recommendation = data.recommendation || '';

      // Populate UI
      verdictEl.textContent = isPhishing ? 'Phishing Detected' : 'Appears Safe';
      verdictEl.style.color = isPhishing ? 'var(--danger)' : 'var(--safe)';
      scoreBadge.textContent = `Score: ${score}`;
      checkedUrl.textContent = url;
      riskLevelEl.textContent = level;

      // reasons list
      reasonsList.innerHTML = '';
      if (reasons && reasons.length) {
        reasons.forEach(r => {
          const li = document.createElement('li');
          li.textContent = r;
          li.className = isPhishing ? 'danger' : 'safe';
          reasonsList.appendChild(li);
        });
      } else {
        const li = document.createElement('li');
        li.textContent = isPhishing ? 'No specific reasons returned.' : 'No issues detected by rules.';
        li.className = isPhishing ? 'danger' : 'safe';
        reasonsList.appendChild(li);
      }

      rawResponse.textContent = JSON.stringify(data, null, 2);
      rawResponse.classList.remove('hidden');

      resultSection.classList.add('show');
      loaderSection.classList.remove('show');

      // add to history
      try {
        const hist = loadHistory();
        hist.unshift({ ts: Date.now(), url, isPhishing, riskScore: score, riskLevel: level });
        saveHistory(hist);
        renderHistory();
      } catch(e) { /* ignore */ }

    } catch (err) {
      alert('Error analyzing URL: ' + err.message);
      loaderSection.classList.remove('show');
    } finally {
      checkBtn.disabled = false;
      checkBtn.textContent = 'Analyze';
    }
  });
});

// Globe initialization
function initGlobe(container) {
  if (typeof THREE === 'undefined') {
    console.error('THREE.js library not loaded');
    return;
  }
  
  const scene = new THREE.Scene();
  const w = container.clientWidth, h = container.clientHeight;
  const camera = new THREE.PerspectiveCamera(45, w/h, 0.1, 1000);
  camera.position.z = 3.5;

  const renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true });
  renderer.setSize(w, h); container.appendChild(renderer.domElement);

  // dotted sphere geometry
  const pointsGeo = new THREE.BufferGeometry();
  const positions = [];
  const color = new THREE.Color(0xFFD400);

  // sample random points on sphere surface
  for (let i=0;i<1200;i++){
    const u = Math.random()*2-1, theta = Math.random()*Math.PI*2;
    const r = Math.sqrt(1 - u*u);
    positions.push(r * Math.cos(theta), r * Math.sin(theta), u);
  }
  pointsGeo.setAttribute('position', new THREE.BufferAttribute(new Float32Array(positions), 3));

  const mat = new THREE.PointsMaterial({ size: 0.02, color: color, transparent: true, opacity: 0.95 });
  const points = new THREE.Points(pointsGeo, mat);
  scene.add(points);

  // soft glow
  const light = new THREE.AmbientLight(0xffffff, 0.6);
  scene.add(light);

  // rotation + pointer parallax
  let rotY = 0;
  const onMove = (e) => {
    const mx = (e.clientX / window.innerWidth) * 2 - 1;
    rotY = mx * 0.3;
  };
  window.addEventListener('mousemove', onMove);

  function animate(){
    requestAnimationFrame(animate);
    points.rotation.y += 0.002 + (rotY - points.rotation.y) * 0.05;
    renderer.render(scene, camera);
  }
  animate();

  // handle resize
  window.addEventListener('resize', ()=> {
    const w2 = container.clientWidth, h2 = container.clientHeight;
    renderer.setSize(w2,h2); camera.aspect = w2/h2; camera.updateProjectionMatrix();
  });
}

// Initialize globe on load
document.addEventListener('DOMContentLoaded', () => {
  const globeContainer = document.getElementById('globe');
  if (globeContainer && typeof THREE !== 'undefined') {
    initGlobe(globeContainer);
  } else if (globeContainer) {
    console.warn('THREE.js not loaded. Globe visualization skipped.');
  }
});