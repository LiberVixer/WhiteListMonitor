# White List Monitor

**White List Monitor** is a Linux desktop utility for monitoring restricted network modes and preparing VPN subscription candidates for whitelist-like environments.

Current release: **0.1.0-alpha1**

This is an alpha build. The core workflow is usable, but the rating model, UI wording, and export format may still change as more real-world test data is collected.

## Features

- Detects router availability, whitelist-only HTTP mode, open internet, and no-internet states.
- Stores VPN subscription URLs in a local SQLite database.
- Downloads, cleans, parses, and deduplicates subscription server rows.
- Calculates a static **S-rating** from 1 to 99 for whitelist suitability.
- Keeps active reachability checks separate in the **e-rating** fields.
- Maintains editable SNI whitelist domains.
- Builds a second SNI domain pool from all subscription servers and helps promote domains into the whitelist.
- Exports ready server lists after the VPN script:
  - `Ready/FB-White-01.txt` ... `Ready/FB-White-10.txt`
  - 999 top RAW rows per file
  - `Ready/FB-White-All.txt` with all candidates
- Runs as a normal Linux desktop app with tray support and scheduled checks.

## Install From DEB

Download the latest alpha `.deb` from GitHub Releases:

```bash
sudo apt update
sudo apt install ./white-list-monitor_0.1.0.alpha1_all.deb
```

Then start it from the Linux Mint menu or run:

```bash
white-list-monitor
```

The package is intended for Linux Mint 22, Ubuntu 24.04, and close Debian/Ubuntu-based desktop systems.

### Runtime Dependencies

The `.deb` package depends on:

- `python3`
- `python3-pyqt6`
- `python3-requests`
- `python3-apscheduler`
- `iputils-ping`

`apt install ./white-list-monitor_0.1.0.alpha1_all.deb` should install them automatically when the repositories are enabled.

## Data Location

User data is stored locally:

```text
~/.config/white-list-monitor/
```

Important files:

- `settings.json` - application settings
- `wl.db` - SQLite database
- `Ready/` - exported server lists

Removing the package does not delete user data.

## Build From Source

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iputils-ping

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m white_list_monitor.main
```

## Build The DEB Package

```bash
./scripts/build_deb.sh
```

The package will be created in:

```text
dist/white-list-monitor_0.1.0.alpha1_all.deb
```

## Development Checks

```bash
python -m unittest
```

## License

MIT License. See [LICENSE](LICENSE).

---

# White List Monitor на русском

**White List Monitor** - настольная Linux-программа для мониторинга режимов сети и подготовки VPN-кандидатов под работу в условиях белых списков.

Текущая версия: **0.1.0-alpha1**

Это альфа-версия. Основной рабочий процесс уже можно использовать, но модель рейтинга, формулировки интерфейса и формат экспорта ещё могут меняться после анализа реальных рабочих серверов.

## Возможности

- Определяет состояние роутера, режим белых списков, открытый интернет и отсутствие интернета.
- Хранит ссылки на VPN-подписки в локальной SQLite-базе.
- Скачивает, очищает, разбирает и дедуплицирует строки серверов из подписок.
- Считает статический **S-рейтинг** от 1 до 99 для пригодности под белые списки.
- Отделяет активную проверку доступности в поля **e-рейтинга**.
- Позволяет вручную редактировать SNI whitelist.
- Ведёт отдельную базу SNI-доменов из подписок и помогает переносить домены в whitelist.
- После VPN-скрипта экспортирует готовые списки:
  - `Ready/FB-White-01.txt` ... `Ready/FB-White-10.txt`
  - по 999 лучших RAW-строк в каждом файле
  - `Ready/FB-White-All.txt` со всеми кандидатами
- Работает как обычное desktop-приложение Linux с треем и планировщиком.

## Установка из DEB

Скачай alpha `.deb` из GitHub Releases:

```bash
sudo apt update
sudo apt install ./white-list-monitor_0.1.0.alpha1_all.deb
```

После установки запусти программу из меню Linux Mint или командой:

```bash
white-list-monitor
```

Пакет рассчитан на Linux Mint 22, Ubuntu 24.04 и близкие Debian/Ubuntu-based desktop-системы.

## Где лежат данные

Пользовательские данные хранятся локально:

```text
~/.config/white-list-monitor/
```

Главные файлы:

- `settings.json` - настройки программы
- `wl.db` - SQLite-база
- `Ready/` - экспортированные списки серверов

Удаление пакета не удаляет пользовательские данные.

## Запуск из исходников

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iputils-ping

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m white_list_monitor.main
```

## Сборка DEB

```bash
./scripts/build_deb.sh
```

Готовый пакет появится здесь:

```text
dist/white-list-monitor_0.1.0.alpha1_all.deb
```

## Проверка разработки

```bash
python -m unittest
```

## Лицензия

MIT License. См. [LICENSE](LICENSE).
