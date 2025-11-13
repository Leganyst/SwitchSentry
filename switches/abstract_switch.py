from abc import ABC, abstractmethod
from typing import Optional, Any, Dict


class AbstarctSwitch(ABC): 
    def __init__(
        self,
        host: str,
        vendor: Optional[str] = None,
        snmp_community: Optional[str] = None,
        snmp_version: int = 2,
        ssh_username: Optional[str] = None,
        ssh_password: Optional[str] = None,
        telnet_username: Optional[str] = None,
        telnet_password: Optional[str] = None,
        http_base_url: Optional[str] = None
        
        ):
        self.host = host
        self.vendor = vendor
        
        # SNMP
        self.snmp_community = snmp_community
        self.snmp_version = snmp_version
        
        # SSH / telnet
        self.ssh_username = ssh_username
        self.ssh_password = ssh_password
        
        self.telnet_username = telnet_username 
        self.telnet_password = telnet_password
        
        # Web
        self.http_base_url = http_base_url
        

    # ==== Низкоуровневые операции, которые могут быть реализованы и в базовом классе ====
    @abstractmethod
    def snmp_get(self, oid: str) -> Any:
        """Базовый SNMP Get"""
        pass
    
    
    @abstractmethod
    def snmp_walk(self, oid: str) -> Dict[str, Any]:
        """SNMP Walk, возвращает таблицу"""
        pass
    
    
    @abstractmethod       
    def ssh_exec(self, cmd: str) -> str:
        """
        Необязательный метод: выполнение команды по SSH.
        Можно оставить пустым, или выбрасывать NotImplemented
        """
        raise NotImplemented
    
    
    @abstractmethod
    def telnet_exec(self, cmd: str) -> str:
        """Метод, аналогичный ssh_exec, но для Telnet"""
        raise NotImplemented
    
    
    @abstractmethod
    def http_check(self, path: str = "/") -> Dict[str, Any]:
        """Простая проверка веб-морды: статус код, время ответа"""
        raise NotImplemented
    
    
    # ==== Высокоуровневая диагностика с унифицированным интерфейсом ====
    @abstractmethod
    def get_sysinfo(self) -> Dict[str, Any]:
        """
        Общая инфа:
            - Модель
            - Версия
            - Uptime
            - Serial
            - etc.
        """
        pass
    
    
    @abstractmethod
    def get_interfaces(self) -> Dict[str, Dict[str, Any]]:
        """
        Список интерфейсов и базовая инфа по каждому.
        Формат:
            { "Gi0/1": {"admin_up": True, "oper_up": True, "speed": 1000, ...}, ... }
        """
        pass
    
    
    @abstractmethod
    def get_interface_stats(self) -> Dict[str, Dict[str, Any]]:
        """
        Статы по портам: octets, errors, discards и т.п.
        Формат:
            { "Gi0/1": {"in_octets": ..., "out_octets": ..., "in_errors": ..., ...}, ... }
        """
        pass
    
    
    @abstractmethod
    def get_resources(self) -> Dict[str, Any]:
        """CPU, память, температура, вентиляторы (если есть возможность извлечь)"""
        pass
        
        
    @abstractmethod
    def get_stp_status(self) -> Dict[str, Any]:
        """Сводка по STP: включен ли, root, роли портов, etc."""
        pass
    
    
    @abstractmethod
    def get_log_summary(self, limit: int = 50) -> Dict[str, Any]:
        """Сводка логов: последния события, ошибки, перегрузки"""
        pass
    
    
    @abstractmethod
    def check_web_ui(self) -> Dict[str, Any]:
        """По умолчанию пытается дернуь http_check, если настроен URL"""
        if not self.http_base_url:
            return {"enabled": False, "reachable": False}
        try:
            resp = self.http_check("/")
            return {"enabled": True, "reachable": True, **resp}
        except NotImplementedError:
            return {"enabled": True, "reachable": False, "error": "http_check not implemented"}
    
    
    @abstractmethod
    def diagnose(self) -> Dict[str, Any]:
        """
        Универсальная точка входа: собрать всё, что можем в один словарь
        Внешний код может вообще не знать, как это происходит внутри - SNMP/SSH/веб
        """
        return {
            "host": self.host,
            "vendor": self.vendor,
            "sysinfo": self.get_sysinfo(),
            "resources": self.get_resources(),
            "interfaces": self.get_interfaces(),
            "interface_stats": self.get_interface_stats(),
            "stp": self.get_stp_status(),
            "logs": self.get_log_summary(),
            "web_ui": self.check_web_ui()
        }