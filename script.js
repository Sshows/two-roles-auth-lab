const form = document.querySelector('#auth-form');
const message = document.querySelector('#message');
let mode = 'login';

function showProfile(account) {
  document.querySelector('#auth-panel').hidden = true;
  document.querySelector('#profile-panel').hidden = false;
  document.querySelector('#profile-email').textContent = account.email;
  document.querySelector('#profile-role').textContent = account.role === 'admin' ? 'Администратор' : 'Пользователь';
}

function showForm() {
  document.querySelector('#profile-panel').hidden = true;
  document.querySelector('#auth-panel').hidden = false;
}

function setMode(next) {
  mode = next;
  message.textContent = '';
  document.querySelector('#login-tab').classList.toggle('active', mode === 'login');
  document.querySelector('#register-tab').classList.toggle('active', mode === 'register');
  document.querySelector('#register-fields').hidden = mode !== 'register';
  document.querySelector('#inviteCode').required = mode === 'register';
  document.querySelector('#password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  document.querySelector('#form-title').textContent = mode === 'login' ? 'С возвращением' : 'Создайте аккаунт';
  document.querySelector('#form-subtitle').textContent = mode === 'login' ? 'Войдите в свою учётную запись' : 'Заполните данные и код приглашения';
  document.querySelector('#submit-button').firstChild.textContent = mode === 'login' ? 'Войти ' : 'Зарегистрироваться ';
}

document.querySelector('#login-tab').addEventListener('click', () => setMode('login'));
document.querySelector('#register-tab').addEventListener('click', () => setMode('register'));

form.addEventListener('submit', async event => {
  event.preventDefault();
  message.textContent = '';
  const button = document.querySelector('#submit-button');
  button.disabled = true;
  const data = Object.fromEntries(new FormData(form));
  try {
    const response = await fetch(`/api/auth?action=${mode}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || 'Ошибка сервера');
    form.reset();
    showProfile(result);
  } catch (error) { message.textContent = error.message; }
  finally { button.disabled = false; }
});

document.querySelector('#logout-button').addEventListener('click', async () => {
  await fetch('/api/auth?action=logout', { method: 'POST' });
  showForm();
  setMode('login');
});

fetch('/api/auth?action=me').then(response => response.ok ? response.json() : null)
  .then(account => { if (account) showProfile(account); });

