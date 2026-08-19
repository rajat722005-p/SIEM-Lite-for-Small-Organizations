/**
 * SIEM-Lite HTML5 Canvas Real-Time SOC Charting Engine
 * Light-weight, zero-dependency charts for log velocity and threat severity.
 */

class SocCharts {
  static renderLineChart(canvasId, dataPoints, labels) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 400;
    const height = canvas.height = 180;

    ctx.clearRect(0, 0, width, height);

    // Padding
    const p = 30;
    const chartW = width - p * 2;
    const chartH = height - p * 2;

    const maxVal = Math.max(...dataPoints, 10);

    // Draw Grid Lines
    ctx.strokeStyle = 'rgba(51, 65, 85, 0.4)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = p + (chartH / 4) * i;
      ctx.beginPath();
      ctx.moveTo(p, y);
      ctx.lineTo(width - p, y);
      ctx.stroke();
    }

    // Draw Line & Area Gradient
    if (dataPoints.length < 2) return;

    ctx.beginPath();
    const stepX = chartW / (dataPoints.length - 1);

    for (let i = 0; i < dataPoints.length; i++) {
      const x = p + i * stepX;
      const y = p + chartH - (dataPoints[i] / maxVal) * chartH;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }

    ctx.strokeStyle = '#06b6d4';
    ctx.lineWidth = 3;
    ctx.stroke();

    // Fill Gradient below line
    ctx.lineTo(p + (dataPoints.length - 1) * stepX, p + chartH);
    ctx.lineTo(p, p + chartH);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, p, 0, height - p);
    grad.addColorStop(0, 'rgba(6, 182, 212, 0.35)');
    grad.addColorStop(1, 'rgba(6, 182, 212, 0.0)');
    ctx.fillStyle = grad;
    ctx.fill();

    // Draw Points
    for (let i = 0; i < dataPoints.length; i++) {
      const x = p + i * stepX;
      const y = p + chartH - (dataPoints[i] / maxVal) * chartH;
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = '#38bdf8';
      ctx.fill();
    }
  }

  static renderDoughnutChart(canvasId, severityCounts) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const width = canvas.width = canvas.parentElement.clientWidth || 300;
    const height = canvas.height = 180;

    ctx.clearRect(0, 0, width, height);

    const total = Object.values(severityCounts).reduce((a, b) => a + b, 0) || 1;
    const colors = {
      CRITICAL: '#f43f5e',
      HIGH: '#f97316',
      MEDIUM: '#f59e0b',
      LOW: '#10b981'
    };

    const centerX = width / 2;
    const centerY = height / 2;
    const outerRadius = Math.min(centerX, centerY) - 15;
    const innerRadius = outerRadius - 22;

    let startAngle = -Math.PI / 2;

    for (const [sev, count] of Object.entries(severityCounts)) {
      if (count === 0) continue;
      const sliceAngle = (count / total) * 2 * Math.PI;
      const endAngle = startAngle + sliceAngle;

      ctx.beginPath();
      ctx.arc(centerX, centerY, outerRadius, startAngle, endAngle);
      ctx.arc(centerX, centerY, innerRadius, endAngle, startAngle, true);
      ctx.closePath();

      ctx.fillStyle = colors[sev] || '#64748b';
      ctx.fill();

      startAngle = endAngle;
    }

    // Center Total Count Text
    ctx.fillStyle = '#f8fafc';
    ctx.font = 'bold 20px JetBrains Mono, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    ctx.fillText(total, centerX, centerY - 5);

    ctx.fillStyle = '#64748b';
    ctx.font = '10px Inter, sans-serif';
    ctx.fillText('ALERTS', centerX, centerY + 14);
  }
}

window.SocCharts = SocCharts;
