export async function renderComment(el, id) {
  const res = await fetch(`/api/comments/${id}`);
  const comment = await res.json();
  el.innerHTML = `<p class="c">${comment.body}</p>`;
}

export function saveSession(accessToken) {
  localStorage.setItem('auth_token', accessToken);
}

export async function runJob(name) {
  const { exec } = require('child_process');
  exec(`convert ${name} -resize 200x200 out.png`);
}

export function track() {
  document.write('<img src="//cdn.example.net/p.gif?u=' + location.hash + '">');
}
