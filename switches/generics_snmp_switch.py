from switches.abstract_switch import AbstractSwitch
from switches.snmp_client import SnmpClient


class GenericSnmpSwitch(AbstractSwitch):
    def __init__(self, host: str, community: str = "public", version: int = 2):
        self.snmp = SnmpClient(host, community, version)

    # =========================
    #  1. Информация о системе
    # =========================
    def get_sysinfo(self):
        """
        Возвращает базовое описание устройства:
        - sysName
        - sysDescr
        - sysObjectID
        - uptime
        """
        sys_name = self.snmp.get("1.3.6.1.2.1.1.5.0")
        sys_descr = self.snmp.get("1.3.6.1.2.1.1.1.0")
        sys_uptime = self.snmp.get("1.3.6.1.2.1.1.3.0")
        sys_oid = self.snmp.get_sysobjectid()

        return {
            "name": sys_name,
            "descr": sys_descr,
            "uptime": sys_uptime,
            "sysObjectID": sys_oid,
        }

    # =========================
    # 2. Список интерфейсов
    # =========================
    def get_interfaces(self):
        """
        Возвращает список интерфейсов по IF-MIB:
        - ifDescr
        - ifType
        - ifAdminStatus
        - ifOperStatus
        """
        descr = self.snmp.walk("1.3.6.1.2.1.2.2.1.2")       # ifDescr
        types = self.snmp.walk("1.3.6.1.2.1.2.2.1.3")       # ifType
        admin = self.snmp.walk("1.3.6.1.2.1.2.2.1.7")       # ifAdminStatus
        oper = self.snmp.walk("1.3.6.1.2.1.2.2.1.8")        # ifOperStatus

        interfaces = {}

        for oid, name in descr.items():
            index = oid.split(".")[-1]
            interfaces[index] = {
                "name": name,
                "type": types.get(f"1.3.6.1.2.1.2.2.1.3.{index}", None),
                "admin_status": admin.get(f"1.3.6.1.2.1.2.2.1.7.{index}", None),
                "oper_status": oper.get(f"1.3.6.1.2.1.2.2.1.8.{index}", None),
            }

        return interfaces

    # =========================
    # 3. Статистика интерфейсов
    # =========================
    def get_interface_stats(self):
        """
        ifInOctets, ifOutOctets и т.п.
        """
        in_octets = self.snmp.walk("1.3.6.1.2.1.2.2.1.10")
        out_octets = self.snmp.walk("1.3.6.1.2.1.2.2.1.16")

        stats = {}

        for oid, value in in_octets.items():
            index = oid.split(".")[-1]
            stats[index] = {
                "in_octets": value,
                "out_octets": out_octets.get(f"1.3.6.1.2.1.2.2.1.16.{index}", None),
            }

        return stats

    # =========================
    # 4. STP (BRIDGE-MIB)
    # =========================
    def get_stp_status(self):
        """
        Возвращает базовый STP-статус:
        - root bridge ID
        - designated ports
        """
        root_bridge = self.snmp.get("1.3.6.1.2.1.17.2.5.0")   # dot1dStpRootIdentifier
        priority = self.snmp.get("1.3.6.1.2.1.17.2.2.0")      # Priority

        return {
            "root_bridge": root_bridge,
            "priority": priority,
        }
