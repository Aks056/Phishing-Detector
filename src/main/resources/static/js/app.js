document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('checkForm');
  const urlInput = document.getElementById('url_input');
  const checkBtn = document.getElementById('checkBtn');
  const clearBtn = document.getElementById('clearBtn');
  const resultSection = document.getElementById('result');
  const verdictEl = document.getElementById('verdict');
  const reasonsList = document.getElementById('reasonsList');
  const checkedUrl = document.getElementById('checkedUrl');
  const scoreBadge = document.getElementById('scoreBadge');
  const riskLevelEl = document.getElementById('riskLevel');
  const rawResponse = document.getElementById('rawResponse');

  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    resultSection.classList.add('hidden');
  });

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    checkBtn.disabled = true;
    checkBtn.textContent = 'Analyzing...';

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

      // Response mapping: adapt to UrlCheckResponse structure
      const isPhishing = data.phishing || data.isPhishing || data.is_phishing || false;
      const score = data.riskScore ?? data.risk_score ?? data.score ?? 0;
      const level = data.riskLevel ?? data.risk_level ?? (score > 50 ? 'HIGH' : (score > 20 ? 'MEDIUM' : 'LOW'));
      const reasons = data.detectedThreats ?? data.threats ?? data.reasons ?? [];

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

      resultSection.classList.remove('hidden');

    } catch (err) {
      alert('Error analyzing URL: ' + err.message);
    } finally {
      checkBtn.disabled = false;
      checkBtn.textContent = 'Analyze';
    }
  });
});