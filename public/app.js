const $ = id => document.getElementById(id);
let token;

async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
  });
  const body = await response.json();
  if (!response.ok) throw new Error(body.detail ?? 'Request failed');
  return body;
}

function show(section) {
  for (const id of ['login', 'enrollment', 'verify', 'documents']) $(id).hidden = id !== section;
  if (section === 'enrollment') $('verify').hidden = false;
  $('message').textContent = '';
}

async function loadDocuments() {
  show('documents');
  const items = await api('/api/documents');
  $('list').replaceChildren();
  for (const item of items) {
    const button = document.createElement('button');
    button.textContent = item.filename;
    button.onclick = async () => {
      try { $('content').textContent = (await api(`/api/documents/${item.id}`)).content; }
      catch (error) { $('message').textContent = error.message; }
    };
    const li = document.createElement('li');
    li.append(button);
    $('list').append(li);
  }
}

$('login').onsubmit = async event => {
  event.preventDefault();
  try {
    const form = new FormData(event.currentTarget);
    const result = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(Object.fromEntries(form)) });
    token = result.token;
    if (result.enrollmentRequired) {
      const enrollment = await api('/api/auth/enroll', { method: 'POST' });
      $('qr').src = enrollment.qrCode;
      $('secret').textContent = enrollment.secret;
      show('enrollment');
    } else show('verify');
  } catch (error) { $('message').textContent = error.message; }
};

$('verify').onsubmit = async event => {
  event.preventDefault();
  try {
    const code = new FormData(event.currentTarget).get('code');
    token = (await api('/api/auth/verify', { method: 'POST', body: JSON.stringify({ code }) })).token;
    $('secret').textContent = '';
    $('qr').removeAttribute('src');
    await loadDocuments();
  } catch (error) { $('message').textContent = error.message; }
};

$('signout').onclick = async () => {
  try { await fetch('/api/auth/logout', { method: 'POST', headers: { Authorization: `Bearer ${token}` } }); }
  finally { token = undefined; $('content').textContent = ''; show('login'); }
};
