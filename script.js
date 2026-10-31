const $ = selector => document.querySelector(selector);
let mode = 'login';
let confirming = false;
let currentEmail = '';

function setMode(next) {
  mode = next;
  confirming = false;
  $('#auth-form').reset();
  $('#message').textContent = '';
  $('#code-fields').hidden = true;
  $('#code').required = false;
  $('#email').readOnly = false;
  $('#details-fields').hidden = false;
  $('#name-field').hidden = mode !== 'register';
  $('#name').required = mode === 'register';
  $('#role-field').hidden = mode !== 'login';
  $('#password').required = true;
  $('#password').autocomplete = mode === 'login' ? 'current-password' : 'new-password';
  $('#login-tab').classList.toggle('active', mode === 'login');
  $('#register-tab').classList.toggle('active', mode === 'register');
  $('#form-title').textContent = mode === 'login' ? 'С возвращением' : 'Создайте аккаунт';
  $('#form-subtitle').textContent = mode === 'login' ? 'Введите почту и пароль' : 'Заполните данные и подтвердите почту';
  $('#submit-button').textContent = mode === 'login' ? 'Войти →' : 'Зарегистрироваться →';
}
function showProfile(account) {
  currentEmail = account.email;
  $('#auth-panel').hidden = true;
  $('#profile-panel').hidden = false;
  $('#profile-name').textContent = account.name || 'Не указано';
  $('#profile-email').textContent = account.email;
  $('#profile-role').textContent = account.role === 'admin' ? 'Администратор' : 'Пользователь';
  $('#cabinet-title').textContent = account.role === 'admin' ? 'Кабинет администратора' : 'Кабинет пользователя';
  $('#admin-panel').hidden = account.role !== 'admin';
  if (account.role === 'admin') loadUsers();
}
async function loadUsers() {
  $('#admin-message').textContent = 'Загрузка…';
  $('#users-list').replaceChildren();
  try {
    const result = await api('users');
    for (const user of result.users) {
      const row = document.createElement('div');
      row.className = 'user-row';
      const label = document.createElement('div');
      label.textContent = `${user.name || 'Без имени'} · ${user.email}`;
      row.append(label);
      if (user.role === 'admin') {
        const badge = document.createElement('small');
        badge.textContent = 'Администратор';
        row.append(badge);
        if (user.email !== currentEmail) {
          const remove = document.createElement('button');
          remove.type = 'button';
          remove.className = 'primary secondary';
          remove.textContent = 'Снять права администратора';
          remove.onclick = async () => {
            if (!confirm(`Снять права администратора у ${user.email}? Аккаунт останется пользователем.`)) return;
            remove.disabled = true;
            try {
              await api('demote', { id: user.id });
              await loadUsers();
              $('#admin-message').textContent = `${user.email} теперь пользователь.`;
            } catch (error) { $('#admin-message').textContent = error.message; remove.disabled = false; }
          };
          row.append(remove);
        }
      } else {
        const button = document.createElement('button');
        button.type = 'button';
        button.className = 'primary secondary';
        button.textContent = 'Назначить администратором';
        button.onclick = async () => {
          if (!confirm(`Назначить ${user.email} администратором? Он сможет назначать других администраторов.`)) return;
          button.disabled = true;
          try {
            await api('promote', { id: user.id });
            await loadUsers();
            $('#admin-message').textContent = `Роль для ${user.email} сохранена. Теперь вход — как администратор.`;
          } catch (error) { $('#admin-message').textContent = error.message; button.disabled = false; }
        };
        row.append(button);
      }
      $('#users-list').append(row);
    }
    $('#admin-message').textContent = result.users.length ? 'Последние 200 аккаунтов' : 'Пользователей пока нет';
  } catch (error) { $('#admin-message').textContent = error.message; }
}
async function api(action, data = {}) {
  const response = await fetch(`/api/auth?action=${action}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(data)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || 'Ошибка сервера');
  return result;
}
$('#login-tab').onclick = () => setMode('login');
$('#register-tab').onclick = () => setMode('register');
$('#change-email').onclick = () => setMode('register');
$('#auth-form').onsubmit = async event => {
  event.preventDefault();
  $('#submit-button').disabled = true;
  $('#message').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(event.target));
    const result = await api(confirming ? 'verify' : mode, data);
    if (mode === 'register' && !confirming) {
      confirming = true;
      $('#details-fields').hidden = true;
      $('#name').required = false;
      $('#password').required = false;
      $('#password').value = '';
      $('#code-fields').hidden = false;
      $('#code').required = true;
      $('#email').readOnly = true;
      $('#submit-button').textContent = 'Подтвердить регистрацию →';
      $('#message').textContent = 'Код отправлен на вашу почту. Он действует 10 минут. Проверьте также папку «Спам».';
      $('#code').focus();
    } else {
      event.target.reset();
      showProfile(result);
    }
  } catch (error) { $('#message').textContent = error.message; }
  finally { $('#submit-button').disabled = false; }
};
$('#logout-button').onclick = async () => {
  try {
    await api('logout');
    $('#profile-panel').hidden = true;
    $('#auth-panel').hidden = false;
    setMode('login');
  } catch { $('#logout-button').textContent = 'Не удалось выйти. Повторить'; }
};
setMode('login');
fetch('/api/auth?action=me').then(r => r.ok ? r.json() : null)
  .then(account => { if (account) showProfile(account); }).catch(() => {});

