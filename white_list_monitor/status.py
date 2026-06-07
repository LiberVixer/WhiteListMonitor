from enum import Enum


class NetworkStatus(str, Enum):
    FREE_INTERNET = "free_internet"
    WHITELIST_MODE = "whitelist_mode"
    NO_INTERNET = "no_internet"
    ROUTER_DOWN = "router_down"
    UNKNOWN = "unknown"


STATUS_LABELS = {
    NetworkStatus.FREE_INTERNET: "Свободный интернет",
    NetworkStatus.WHITELIST_MODE: "Белые списки",
    NetworkStatus.NO_INTERNET: "Интернет не работает",
    NetworkStatus.ROUTER_DOWN: "Роутер недоступен",
    NetworkStatus.UNKNOWN: "Неизвестно",
}


STATUS_TOOLTIPS = {
    NetworkStatus.FREE_INTERNET: "Один из kwork.ru, tmsmm.ru, rsload.net отвечает по HTTP",
    NetworkStatus.WHITELIST_MODE: "Один из vk.com, ya.ru, mail.ru отвечает, открытые сайты не отвечают",
    NetworkStatus.NO_INTERNET: "HTTP-проверки не проходят, роутер пингуется",
    NetworkStatus.ROUTER_DOWN: "Роутер не пингуется",
    NetworkStatus.UNKNOWN: "Статус еще не определен",
}
