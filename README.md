# White List Monitor

GUI/tray application for Linux Mint that monitors network state, stores VPN subscription URLs in SQLite, and schedules a VPN filtering script.

The VPN script assigns a one-time static S-rating per unique server URI. Static filtering marks each parsed URI as BAD or CANDIDATE for Russia whitelist mode; BAD rows get no useful S-rating, while CANDIDATE rows receive a stable 1-99 score based only on protocol, TLS/Reality, SNI whitelist fit, port, transport, fingerprint, and related URI fields. Active reachability stays separate in the extended e-rating.

The app also has an explicit "Пересчитать S-рейтинг в базе" action. It is a manual reset/rebuild for static BAD/CANDIDATE and S-rating fields only; e-rating fields are preserved.

## Install

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip iputils-ping
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
python -m white_list_monitor.main
```

The database `wl.db` and config file are created automatically on first run.
