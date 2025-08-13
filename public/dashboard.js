document.addEventListener('DOMContentLoaded', async () => {
  // Helper to fetch JSON with error handling
  async function fetchJSON(url, options = {}) {
    const res = await fetch(url, options);
    if (res.status === 401) {
      window.location.href = '/auth/login.html';
      return null;
    }
    if (!res.ok) throw new Error(await res.text());
    return res.json();
  }

  // Format timestamp to IST - helper function to convert to IST
  function formatToIST(utcTimestamp) {
    return new Date(utcTimestamp).toLocaleString('en-IN', {
      timeZone: 'Asia/Kolkata',
      day: '2-digit',
      month: 'short',
      year: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: true
    }) + ' IST';
  }

  // For admin search
  let lastSearch = '';
  let lastAction = '';
  let lastDetails = '';
  async function loadDashboard(search = '', action = '', details = '') {
    let url = '/api/dashboard/summary';
    const params = [];
    if (search) params.push(`search=${encodeURIComponent(search)}`);
    if (action) params.push(`action=${encodeURIComponent(action)}`);
    if (details) params.push(`details=${encodeURIComponent(details)}`);
    if (params.length) url += '?' + params.join('&');
    try {
      const summary = await fetchJSON(url);
      if (!summary) return;
      // Normal user view
      if (!summary.isAdmin) {
        document.getElementById('loginCount').textContent = summary.loginCount;
        document.getElementById('urlCount').textContent = summary.urlCount;
        document.getElementById('lastLogin').textContent = summary.lastLogin || '-';
        // Hide username column
        document.getElementById('usernameHeader').style.display = 'none';
        // Populate activity log table
        const tbody = document.getElementById('activityTableBody');
        tbody.innerHTML = '';
        summary.activityLogs.forEach(log => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${formatToIST(log.timestamp)}</td><td>${log.action}</td><td>${log.details || ''}</td>`;
          tbody.appendChild(tr);
        });
        document.getElementById('adminSection').style.display = 'none';
      } else {
        // Admin view
        document.getElementById('adminSection').style.display = '';
        // Hide normal user summary
        document.querySelector('.user-summary').style.display = 'none';
        // Show username column in activity table
        document.getElementById('usernameHeader').style.display = '';
        // Combine all activity logs for admin activity table
        let allLogs = [];
        summary.userStats.forEach(user => {
          allLogs = allLogs.concat(user.activityLogs.map(log => ({ ...log, username: user.username })));
        });
        // Sort by timestamp desc
        allLogs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        // Fill admin activity logs table
        const adminTbody = document.getElementById('adminActivityTableBody');
        adminTbody.innerHTML = '';
        allLogs.forEach(log => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${log.username}</td><td>${formatToIST(log.timestamp)}</td><td>${log.action}</td><td>${log.details || ''}</td>`;
          adminTbody.appendChild(tr);
        });
        // Fill user management table
        const userTbody = document.getElementById('userTableBody');
        userTbody.innerHTML = '';
        summary.userStats.forEach(user => {
          const tr = document.createElement('tr');
          tr.innerHTML = `
            <td>${user.userId}</td>
            <td>${user.username}</td>
            <td>${user.role || 'user'}</td>
            <td>
              <select data-user-id="${user.userId}" class="role-select">
                <option value="user" ${user.role === 'user' ? 'selected' : ''}>user</option>
                <option value="admin" ${user.role === 'admin' ? 'selected' : ''}>admin</option>
              </select>
            </td>
          `;
          userTbody.appendChild(tr);
        });
        // Fill activity log table (for admin, show all logs with username)
        const tbody = document.getElementById('activityTableBody');
        tbody.innerHTML = '';
        allLogs.forEach(log => {
          const tr = document.createElement('tr');
          tr.innerHTML = `<td>${log.username}</td><td>${formatToIST(log.timestamp)}</td><td>${log.action}</td><td>${log.details || ''}</td>`;
          tbody.appendChild(tr);
        });
        // Handle role change
        userTbody.addEventListener('change', async (e) => {
          if (e.target.classList.contains('role-select')) {
            const userId = e.target.getAttribute('data-user-id');
            const newRole = e.target.value;
            try {
              await fetchJSON('/admin/change-role', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ userId, newRole })
              });
              alert('Role updated!');
              loadDashboard(lastSearch, lastAction, lastDetails);
            } catch (err) {
              alert('Failed to update role: ' + err.message);
            }
          }
        });
      }
    } catch (err) {
      alert('Failed to load dashboard: ' + err.message);
    }
  }

  // Initial load
  loadDashboard();

  // Admin search filter
  const userSearchInput = document.getElementById('userSearchInput');
  if (userSearchInput) {
    userSearchInput.addEventListener('input', function() {
      lastSearch = this.value.trim();
      loadDashboard(lastSearch, lastAction, lastDetails);
    });
  }
  // Admin activity log filters
  const adminUserSearchInput = document.getElementById('adminUserSearchInput');
  const adminActionSearchInput = document.getElementById('adminActionSearchInput');
  const adminDetailsSearchInput = document.getElementById('adminDetailsSearchInput');
  if (adminUserSearchInput && adminActionSearchInput && adminDetailsSearchInput) {
    adminUserSearchInput.addEventListener('input', function() {
      lastSearch = this.value.trim();
      loadDashboard(lastSearch, lastAction, lastDetails);
    });
    adminActionSearchInput.addEventListener('input', function() {
      lastAction = this.value.trim();
      loadDashboard(lastSearch, lastAction, lastDetails);
    });
    adminDetailsSearchInput.addEventListener('input', function() {
      lastDetails = this.value.trim();
      loadDashboard(lastSearch, lastAction, lastDetails);
    });
  }
});