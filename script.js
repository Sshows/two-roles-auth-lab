const $ = selector => document.querySelector(selector);
let step = 'send';
let mode = 'login';

function resetForm() {
  step = 'send';
  $('#code-fields').hidden = true;
  $('#code').required = false;
  $('#code').value = '';
  $('#email').readOnly = false;
  $('#submit-button').textContent = 'Получить код →';
  $('#message').textContent = '';
}
function showProfile(account) {
  $('#auth-panel').hidden = true;
  $('#profile-panel').hidden = false;
  $('#profile-email').textContent = account.email;
  $('#profile-role').textContent = account.role === 'admin' ? 'Администратор' : 'Пользователь';
}
function setMode(next) {
  mode = next;
  resetForm();
  $('#login-tab').classList.toggle('active', mode === 'login');
  $('#register-tab').classList.toggle('active', mode === 'register');
  $('#form-title').textContent = mode === 'login' ? 'С возвращением' : 'Создайте аккаунт';
  $('#form-subtitle').textContent = 'Отправим одноразовый код на вашу почту';
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
$('#change-email').onclick = resetForm;
$('#auth-form').onsubmit = async event => {
  event.preventDefault();
  $('#submit-button').disabled = true;
  $('#message').textContent = '';
  try {
    const data = Object.fromEntries(new FormData(event.target));
    const result = await api(step, data);
    if (step === 'send') {
      step = 'verify';
      $('#code-fields').hidden = false;
      $('#code').required = true;
      $('#email').readOnly = true;
      $('#submit-button').textContent = 'Подтвердить и войти →';
      $('#message').textContent = 'Письмо отправлено. Проверьте также папку «Спам». Код действует 10 минут.';
      $('#code').focus();
    } else {
      event.target.reset();
      resetForm();
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
fetch('/api/auth?action=me').then(r => r.ok ? r.json() : null)
  .then(account => { if (account) showProfile(account); }).catch(() => {});

