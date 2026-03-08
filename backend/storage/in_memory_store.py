class AlertStore:
    def __init__(self):
        self._alerts = {}

    def add(self, alert: dict):
        self._alerts[alert["id"]] = alert

    def get_all(self):
        return list(self._alerts.values())

    def get_by_id(self, alert_id: str):
        return self._alerts.get(alert_id)

    def close(self, alert_id: str) -> bool:
        if alert_id in self._alerts:
            self._alerts[alert_id]["status"] = "CLOSED"
            return True
        return False