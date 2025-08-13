// Dynamically injects the navbar into #navbar-root
(async function() {
    // Load HTML
    const resp = await fetch('/components/navbar/navbar.html');
    const html = await resp.text();
    const root = document.getElementById('navbar-root');
    if (!root) return;
    root.innerHTML = html;
  
    // Load CSS
    const cssId = 'navbar-css';
    if (!document.getElementById(cssId)) {
      const link = document.createElement('link');
      link.id = cssId;
      link.rel = 'stylesheet';
      link.href = '/components/navbar/navbar.css';
      document.head.appendChild(link);
    }
  
    // Hamburger logic
    const hamburger = document.getElementById('navbar-hamburger');
    const flyout = document.getElementById('navbar-flyout');
    let open = false;
  
    function closeMenu() {
      flyout.style.display = 'none';
      open = false;
    }
    function openMenu() {
      flyout.style.display = 'block';
      open = true;
    }
  
    hamburger.addEventListener('click', (e) => {
      e.stopPropagation();
      if (open) closeMenu();
      else openMenu();
    });
  
    // Close on click outside
    document.addEventListener('click', (e) => {
      if (open && !flyout.contains(e.target) && !hamburger.contains(e.target)) {
        closeMenu();
      }
    });
  
    // Optional: close on ESC
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeMenu();
    });
  })();