"""
alerter.py — Gerenciamento e persistência de alertas
"""

import json
import os
import time
from collections import deque
from datetime import datetime

LOG_DIR = "logs"
MAX_RECENT = 100  # alertas recentes mantidos em memória


class Alerter:
    def __init__(self, log_dir=LOG_DIR):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)

        self.log_file = os.path.join(
            log_dir,
            f"ids_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl",
        )

        # Fila circular de alertas recentes (exibida no dashboard)
        self.recent_alerts: deque = deque(maxlen=MAX_RECENT)

        # Contadores por severidade
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def add_alert(self, alert: dict):
        """Registra um novo alerta em memória e em disco."""
        alert["timestamp"] = datetime.now().strftime("%H:%M:%S")
        alert["epoch"] = time.time()

        # Atualiza contadores
        sev = alert.get("severity", "LOW")
        self.counts[sev] = self.counts.get(sev, 0) + 1

        # Armazena em memória
        self.recent_alerts.appendleft(alert)

        # Persiste em arquivo JSONL
        with open(self.log_file, "a") as f:
            f.write(json.dumps(alert) + "\n")

    def get_recent(self, n=20):
        """Retorna os N alertas mais recentes."""
        return list(self.recent_alerts)[:n]

    def get_counts(self):
        return dict(self.counts)

    def get_log_path(self):
        return self.log_file
