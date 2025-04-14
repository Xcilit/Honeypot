from flask import Flask, request, render_template, redirect, url_for, session
from functools import wraps
import time
import subprocess
import logging
import json
from user_agents import parse  # Для парсинга данных о браузере и ОС
from scapy.all import ARP, Ether, srp  # Для ARP-запросов
import os

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Установите секретный ключ для сессий

# Белый список IP-адресов
allowed_ips = {'192.168.200.210'}  # Начальные IP-адреса
attempts = {}


# Уровень ограничения доступа (от 0 до 5)
restriction_level = 0


# Список пользователей
users = {'admin': 'adminpass'}  # Начальные данные для авторизации (логин: пароль)

# Простая проверка учетных данных
admin_credentials = {'username': 'admin', 'password': 'admin'}

log_dir = os.path.join(os.getcwd(), 'logs')
os.makedirs(log_dir, exist_ok=True)

log_path = os.path.join(os.getcwd(), 'intruder_logs.txt')
json_path = os.path.join(log_dir, 'intruder_logs.json')
logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(message)s')


def scan_ip(ip):
    try:
        result = subprocess.run(['nmap', '-A', ip], capture_output=True, text=True, timeout=10)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "Сканирование завершилось по тайм-ауту"
    except Exception as e:
        return f"Ошибка при сканировании: {e}"

@app.before_request
def log_request_info():
    user_ip = request.remote_addr
    if user_ip not in allowed_ips:
        logging.info(f"Неавторизованный доступ от IP: {user_ip}")
        scan_results = scan_ip(user_ip)
        logging.info(f"Результаты сканирования для IP {user_ip}:\n{scan_results}")
        
def log_intruder(ip, user_agent):
    # Парсим данные о браузере и операционной системе
    user_agent_info = parse(user_agent)

    # Получаем MAC-адрес через ARP-запрос
    mac_address = get_mac_address(ip)

    # Формируем данные для записи в JSON формате
    log_data = {
        'IP Address': ip,
        'MAC Address': mac_address,
        'Operating System': user_agent_info.os.family,
        'OS Version': user_agent_info.os.version_string,
        'Browser': user_agent_info.browser.family,
        'Browser Version': user_agent_info.browser.version_string
    }

    # Записываем в файл JSON
    with open(json_path, 'a') as f:
        json.dump(log_data, f)
        f.write("\n")  # Для разделения записей в файле

# Функция для получения MAC-адреса через ARP-запрос
def get_mac_address(ip):
    # Отправляем ARP-запрос для получения MAC-адреса
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    
    result = srp(packet, timeout=3, verbose=False)[0]

    if result:
        return result[0][1].hwsrc  # Возвращаем MAC-адрес
    else:
        return "Unknown"  # Если MAC-адрес не найден

def get_delay_by_restriction():
    level_to_delay = {
        0: 0,
        1: 2,
        2: 4,
        3: 6,
        4: 8,
        5: 10
    }
    return level_to_delay.get(restriction_level, 0)

def generate_attack_summary():
    try:
        with open('intruder_logs.json', 'r') as f:
            lines = f.readlines()
        summary = {}
        for line in lines:
            if not line.strip():
                continue
            try:
                entry = json.loads(line)
                threat = entry.get('Threat Type', 'unknown')
                summary[threat] = summary.get(threat, 0) + 1
            except json.JSONDecodeError:
                continue
        return summary
    except FileNotFoundError:
        return {}

# Декоратор для защиты админской панели
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

# Главная страница с авторизацией
@app.route('/')
def login():
    return render_template('login.html')

# Обработка авторизации
@app.route('/authorize', methods=['POST'])
def authorize():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    # Проверка, в белом ли списке IP
    if ip not in allowed_ips:
        time.sleep(get_delay_by_restriction())
        if attempts.get(ip, 0) >= 3:
            return "Доступ заблокирован.", 403

        time.sleep(3)  # Задержка для подозрительных IP
        log_intruder(ip, user_agent)
        attempts[ip] = attempts.get(ip, 0) + 1
        return "Ошибка авторизации. Плохое соединение.", 403

    # Проверка логина и пароля
    username = request.form['username']
    password = request.form['password']
    if username in users and users[username] == password:
        return redirect(url_for('home'))
    else:
        return "Неверные учетные данные. Попробуйте снова.", 403

# Домашняя страница для авторизованных пользователей
@app.route('/home')
def home():
    return "Добро пожаловать в систему!"

# Страница входа в админскую панель
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username == admin_credentials['username'] and password == admin_credentials['password']:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            error = 'Неверный логин или пароль'
            return render_template('admin_login.html', error=error)

    return render_template('admin_login.html')
# Админская панель
@app.route('/admin')
@login_required
def admin_panel():
    try:
        with open('intruder_logs.txt', 'r') as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = []

    summary = generate_attack_summary()

    return render_template('admin_panel.html',
                           allowed_ips=allowed_ips,
                           users=users,
                           logs=logs,
                           summary=summary,
                           current_restriction=restriction_level,
                           confirmation_message=None)


# Добавление IP-адреса через админскую панель
@app.route('/admin/add_ip', methods=['POST'])
@login_required
def add_ip():
    new_ip = request.form['new_ip']
    allowed_ips.add(new_ip)
    return redirect(url_for('admin_panel'))

# Добавление пользователя через админскую панель
@app.route('/admin/add_user', methods=['POST'])
@login_required
def add_user():
    new_user = request.form['new_user']
    new_password = request.form['new_password']
    users[new_user] = new_password
    return redirect(url_for('admin_panel'))

# Просмотр логов о неудачных попытках
@app.route('/admin/logs')
@login_required
def view_logs():
    with open(log_path, 'r') as f:
        logs = f.readlines()
    return render_template('logs.html', logs=logs)

# Выход из админской панели
@app.route('/admin/logout')
@login_required
def admin_logout():
    session.pop('logged_in', None)
    return redirect(url_for('admin_login'))

@app.route('/admin/clear_logs', methods=['POST'])
@login_required
def clear_logs():
    open('intruder_logs.txt', 'w').close()
    open('intruder_logs.json', 'w').close()
    return redirect(url_for('admin_panel'))

@app.route('/admin/set_restriction', methods=['POST'])
@login_required
def set_restriction():
    global restriction_level
    try:
        restriction_level = int(request.form['restriction_level'])
    except ValueError:
        restriction_level = 0

    try:
        with open('intruder_logs.txt', 'r') as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = []

    summary = generate_attack_summary()

    return render_template('admin_panel.html',
                           allowed_ips=allowed_ips,
                           users=users,
                           logs=logs,
                           summary=summary,
                           current_restriction=restriction_level,
                           confirmation_message=f'Уровень {restriction_level} применён (задержка {get_delay_by_restriction()} сек)')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
    #fasdfasfas
