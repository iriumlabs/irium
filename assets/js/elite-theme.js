(function eliteThemeInit(){
  if (!document.querySelector('.tech-bg')) {
    const stars = document.querySelector('.stars');
    if (stars && stars.parentNode) {
      const bg = document.createElement('div');
      bg.className = 'tech-bg';
      bg.setAttribute('aria-hidden', 'true');
      stars.insertAdjacentElement('afterend', bg);
    }
  }

  if (window.matchMedia('(hover: none), (pointer: coarse)').matches) return;
  if (document.getElementById('cursor-dust-canvas')) return;

  const canvas = document.createElement('canvas');
  canvas.id = 'cursor-dust-canvas';
  canvas.className = 'cursor-dust-canvas';
  canvas.setAttribute('aria-hidden', 'true');
  document.body.appendChild(canvas);

  const ctx = canvas.getContext('2d', { alpha: true });
  if (!ctx) return;

  const colors = ['110,198,255', '141,125,255', '95,225,255'];
  let dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
  let tx = window.innerWidth * 0.5;
  let ty = window.innerHeight * 0.5;
  let lastX = tx;
  let lastY = ty;
  const particles = [];

  function resize(){
    dpr = Math.max(1, Math.min(2, window.devicePixelRatio || 1));
    canvas.width = Math.floor(window.innerWidth * dpr);
    canvas.height = Math.floor(window.innerHeight * dpr);
    canvas.style.width = window.innerWidth + 'px';
    canvas.style.height = window.innerHeight + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }

  function spawn(x, y, strength){
    const count = Math.min(10, 3 + Math.floor(strength / 9));
    for (let i = 0; i < count; i++) {
      const a = Math.random() * Math.PI * 2;
      const speed = 0.5 + Math.random() * 1.9 + strength * 0.012;
      particles.push({
        x, y,
        vx: Math.cos(a) * speed,
        vy: Math.sin(a) * speed,
        life: 24 + Math.random() * 24,
        ttl: 24 + Math.random() * 24,
        r: 0.9 + Math.random() * 2.0,
        c: colors[(Math.random() * colors.length) | 0]
      });
    }
    if (particles.length > 220) particles.splice(0, particles.length - 220);
  }

  function draw(){
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (let i = particles.length - 1; i >= 0; i--) {
      const p = particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.vx *= 0.982;
      p.vy *= 0.982;
      p.life -= 1;
      if (p.life <= 0) { particles.splice(i, 1); continue; }
      const alpha = p.life / p.ttl;
      ctx.beginPath();
      ctx.fillStyle = 'rgba(' + p.c + ',' + (0.78 * alpha) + ')';
      ctx.arc(p.x, p.y, p.r + (1 - alpha) * 0.5, 0, Math.PI * 2);
      ctx.fill();
    }
    requestAnimationFrame(draw);
  }

  function onMove(e){
    tx = e.clientX;
    ty = e.clientY;
    const dx = tx - lastX;
    const dy = ty - lastY;
    const speed = Math.hypot(dx, dy);
    if (speed > 0.8) spawn(tx, ty, speed);
    lastX = tx;
    lastY = ty;
  }

  resize();
  window.addEventListener('resize', resize, { passive: true });
  document.addEventListener('mousemove', onMove, { passive: true });
  requestAnimationFrame(draw);
})();
