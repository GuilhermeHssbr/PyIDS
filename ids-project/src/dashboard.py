"""
dashboard.py — Dashboard interativo no terminal (curses)
"""

import curses
import time
import threading
from datetime import datetime


SEVERITY_COLORS = {
    "CRITICAL": 1,   # vermelho
    "HIGH":     2,   # amarelo
    "MEDIUM":   3,   # ciano
    "LOW":      4,   # verde
}

REFRESH_RATE = 0.5  # segundos


class Dashboard:
    def __init__(self, alerter):
        self.alerter = alerter
        self.stats = {}
        self.running = False
        self._lock = threading.Lock()
        self.stdscr = None

    def update_stats(self, stats: dict):
        with self._lock:
            self.stats = dict(stats)

    def stop(self):
        self.running = False

    def run(self):
        """Ponto de entrada: inicializa curses e entra no loop de renderização."""
        curses.wrapper(self._main_loop)

    # ------------------------------------------------------------------ #
    #  Loop principal                                                      #
    # ------------------------------------------------------------------ #

    def _main_loop(self, stdscr):
        self.stdscr = stdscr
        self.running = True

        # Configurações de curses
        curses.curs_set(0)
        stdscr.nodelay(True)
        curses.start_color()
        curses.use_default_colors()

        # Define pares de cores
        curses.init_pair(1, curses.COLOR_RED,     -1)   # CRITICAL
        curses.init_pair(2, curses.COLOR_YELLOW,  -1)   # HIGH
        curses.init_pair(3, curses.COLOR_CYAN,    -1)   # MEDIUM
        curses.init_pair(4, curses.COLOR_GREEN,   -1)   # LOW / ok
        curses.init_pair(5, curses.COLOR_WHITE,   -1)   # texto normal
        curses.init_pair(6, curses.COLOR_BLACK,   curses.COLOR_WHITE)  # header

        while self.running:
            stdscr.erase()
            h, w = stdscr.getmaxyx()

            try:
                self._draw_header(stdscr, w)
                self._draw_stats(stdscr, w)
                self._draw_alerts(stdscr, w, h)
                self._draw_footer(stdscr, h, w)
            except curses.error:
                pass  # terminal muito pequeno; ignora

            stdscr.refresh()

            # Captura tecla 'q' para sair
            key = stdscr.getch()
            if key in (ord("q"), ord("Q")):
                self.running = False
                break

            time.sleep(REFRESH_RATE)

    # ------------------------------------------------------------------ #
    #  Seções do dashboard                                                 #
    # ------------------------------------------------------------------ #

    def _draw_header(self, scr, w):
        title = " 🛡  PyIDS — Intrusion Detection System "
        ts    = datetime.now().strftime(" %Y-%m-%d  %H:%M:%S ")
        scr.attron(curses.color_pair(6) | curses.A_BOLD)
        scr.addstr(0, 0, title.ljust(w - len(ts)))
        scr.addstr(0, w - len(ts), ts)
        scr.attroff(curses.color_pair(6) | curses.A_BOLD)
        scr.addstr(1, 0, "─" * w, curses.color_pair(5))

    def _draw_stats(self, scr, w):
        with self._lock:
            s = dict(self.stats)

        counts = self.alerter.get_counts()
        log_path = self.alerter.get_log_path()

        # Linha 2 — tráfego
        scr.addstr(2, 2, "TRÁFEGO", curses.A_BOLD | curses.color_pair(5))
        cols = [
            ("Pacotes",  str(s.get("packets_total", 0))),
            ("TCP",      str(s.get("packets_tcp", 0))),
            ("UDP",      str(s.get("packets_udp", 0))),
            ("ICMP",     str(s.get("packets_icmp", 0))),
            ("ARP",      str(s.get("packets_arp", 0))),
            ("Bytes",    self._human_bytes(s.get("bytes_total", 0))),
        ]
        x = 2
        for label, val in cols:
            scr.addstr(3, x, f"{label}: ", curses.color_pair(5))
            scr.addstr(val + "  ", curses.A_BOLD | curses.color_pair(4))
            x += len(label) + len(val) + 4

        # Linha 4 — alertas por severidade
        scr.addstr(5, 2, "ALERTAS", curses.A_BOLD | curses.color_pair(5))
        x = 2
        for sev, color in SEVERITY_COLORS.items():
            cnt = counts.get(sev, 0)
            scr.addstr(6, x, f"{sev}: ")
            scr.addstr(str(cnt) + "  ", curses.A_BOLD | curses.color_pair(color))
            x += len(sev) + len(str(cnt)) + 4

        scr.addstr(6, x + 4, f"Log → {log_path}", curses.color_pair(5) | curses.A_DIM)
        scr.addstr(7, 0, "─" * w, curses.color_pair(5))

    def _draw_alerts(self, scr, w, h):
        scr.addstr(8, 2, "ALERTAS RECENTES", curses.A_BOLD | curses.color_pair(5))

        # Cabeçalho da tabela
        header = f"{'HORA':<10} {'SEV':<10} {'TIPO':<25} {'ORIGEM':<18} DETALHE"
        scr.addstr(9, 2, header, curses.A_UNDERLINE | curses.color_pair(5))

        alerts = self.alerter.get_recent(n=h - 13)
        row = 10
        for alert in alerts:
            if row >= h - 3:
                break
            sev   = alert.get("severity", "LOW")
            color = SEVERITY_COLORS.get(sev, 5)
            line  = (
                f"{alert.get('timestamp',''):<10} "
                f"{sev:<10} "
                f"{alert.get('type',''):<25} "
                f"{alert.get('src_ip',''):<18} "
                f"{alert.get('detail','')}"
            )
            # Trunca se ultrapassar largura do terminal
            line = line[: w - 3]
            scr.addstr(row, 2, line, curses.color_pair(color))
            row += 1

        if not alerts:
            scr.addstr(10, 2, "Nenhum alerta detectado ainda…",
                       curses.A_DIM | curses.color_pair(4))

    def _draw_footer(self, scr, h, w):
        footer = "  [Q] Sair  |  Atualiza a cada 500ms  |  Logs salvos automaticamente  "
        scr.addstr(h - 1, 0, footer[:w].ljust(w),
                   curses.color_pair(6))

    # ------------------------------------------------------------------ #
    #  Utilitários                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _human_bytes(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f}{unit}"
            n /= 1024
        return f"{n:.1f}TB"
