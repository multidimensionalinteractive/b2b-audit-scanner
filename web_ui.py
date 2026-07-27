#!/usr/bin/env python3
"""Simple web UI for the B2B Audit Scanner — single file Flask app."""
import os
from flask import Flask, request, jsonify, render_template_string
from scanner import scan_url

app = Flask(__name__)

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>B2B Security Scanner</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; background: #0a0a0a; color: #e0e0e0; }
    .container { max-width: 800px; margin: 0 auto; padding: 2rem; }
    h1 { font-size: 2rem; margin-bottom: 0.5rem; }
    p.subtitle { color: #888; margin-bottom: 2rem; }
    .form-group { display: flex; gap: 0.5rem; margin-bottom: 2rem; }
    input { flex: 1; padding: 0.75rem 1rem; border: 1px solid #333; border-radius: 0.5rem; background: #1a1a1a; color: #fff; font-size: 1rem; }
    input:focus { outline: none; border-color: #3b82f6; }
    button { padding: 0.75rem 1.5rem; background: #3b82f6; color: #fff; border: none; border-radius: 0.5rem; font-size: 1rem; cursor: pointer; }
    button:hover { background: #2563eb; }
    button:disabled { background: #555; cursor: not-allowed; }
    .results { background: #1a1a1a; border: 1px solid #333; border-radius: 0.5rem; padding: 1.5rem; margin-top: 1rem; }
    .score { font-size: 3rem; font-weight: 700; }
    .grade { font-size: 1.5rem; font-weight: 600; }
    .header-row { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #222; }
    .header-row:last-child { border-bottom: none; }
    .pass { color: #22c55e; }
    .warn { color: #eab308; }
    .fail { color: #ef4444; }
    .plans { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; margin-top: 3rem; }
    .plan { background: #1a1a1a; border: 1px solid #333; border-radius: 0.5rem; padding: 1.5rem; text-align: center; }
    .plan.popular { border-color: #3b82f6; position: relative; }
    .plan.popular::before { content: "POPULAR"; position: absolute; top: -0.75rem; left: 50%; transform: translateX(-50%); background: #3b82f6; color: #fff; font-size: 0.65rem; padding: 0.15rem 0.75rem; border-radius: 0.25rem; }
    .plan h3 { margin-bottom: 0.5rem; }
    .plan .price { font-size: 2rem; font-weight: 700; margin-bottom: 1rem; }
    .plan ul { list-style: none; margin-bottom: 1.5rem; }
    .plan li { padding: 0.25rem 0; color: #888; }
    .plan button { width: 100%; }
    .loading { text-align: center; padding: 2rem; color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <h1>B2B Security Scanner</h1>
    <p class="subtitle">Check any website's security headers and get a grade in seconds.</p>

    <form class="form-group" id="scanForm">
      <input type="url" id="urlInput" placeholder="https://example.com" required />
      <button type="submit" id="scanBtn">Scan Now</button>
    </form>

    <div id="loading" class="loading" style="display:none;">Scanning... please wait.</div>

    <div id="results" style="display:none;">
      <div class="results">
        <div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">
          <div class="score" id="scoreDisplay"></div>
          <div><div class="grade" id="gradeDisplay"></div></div>
        </div>
        <h3 style="margin-bottom:0.5rem;">Headers Breakdown</h3>
        <div id="headersList"></div>
      </div>

      <div class="plans">
        <div class="plan">
          <h3>Basic</h3>
          <div class="price">$5/mo</div>
          <ul>
            <li>1 domain scan</li>
            <li>Monthly reports</li>
            <li>CSV export</li>
          </ul>
          <button type="button" onclick="alert('Coming soon!')">Start Free Trial</button>
        </div>
        <div class="plan popular">
          <h3>Pro</h3>
          <div class="price">$10/mo</div>
          <ul>
            <li>10 domain scans</li>
            <li>Weekly reports</li>
            <li>Email alerts</li>
            <li>CSV export</li>
          </ul>
          <button type="button" onclick="alert('Coming soon!')">Start Free Trial</button>
        </div>
        <div class="plan">
          <h3>Enterprise</h3>
          <div class="price">$50/mo</div>
          <ul>
            <li>Unlimited domains</li>
            <li>Daily reports</li>
            <li>Slack alerts</li>
            <li>API access</li>
          </ul>
          <button type="button" onclick="alert('Coming soon!')">Start Free Trial</button>
        </div>
      </div>
    </div>
  </div>

  <script>
    document.getElementById('scanForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const url = document.getElementById('urlInput').value;
      if (!url) return;
      document.getElementById('loading').style.display = 'block';
      document.getElementById('results').style.display = 'none';
      document.getElementById('scanBtn').disabled = true;

      try {
        const resp = await fetch('/api/scan?url=' + encodeURIComponent(url));
        const data = await resp.json();
        document.getElementById('loading').style.display = 'none';
        document.getElementById('results').style.display = 'block';

        document.getElementById('scoreDisplay').textContent = data.score;
        document.getElementById('gradeDisplay').textContent = 'Grade: ' + data.grade;

        const headersList = document.getElementById('headersList');
        headersList.innerHTML = '';
        (data.headers || []).forEach(h => {
          const row = document.createElement('div');
          row.className = 'header-row';
          const cls = h.status === 'pass' ? 'pass' : h.status === 'warn' ? 'warn' : 'fail';
          row.innerHTML = '<span>' + h.name + '</span><span class="' + cls + '">' + h.status + '</span>';
          headersList.appendChild(row);
        });
      } catch (err) {
        alert('Scan failed: ' + err.message);
      } finally {
        document.getElementById('scanBtn').disabled = false;
      }
    });
  </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML)

@app.route('/api/scan')
def api_scan():
    url = request.args.get('url')
    if not url:
        return jsonify({'error': 'url required'}), 400
    if not url.startswith('http'):
        url = 'https://' + url
    r = scan_url(url); result = {'score': r.score, 'grade': r.grade, 'headers': [{'name': h.header, 'status': 'pass' if h.found else ('warn' if not h.required else 'fail') , 'value': h.value} for h in r.checks]}
    return jsonify({
        'url': url,
        'score': result['score'],
        'grade': result['grade'],
        'headers': result['headers'],
    })

if __name__ == '__main__':
    print("Starting B2B Security Scanner UI on http://localhost:5000")
    app.run(host='127.0.0.1', port=5000, debug=True)