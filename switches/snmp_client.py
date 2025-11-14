import asyncio


from typing import Any, Dict
from pysnmp.hlapi.v3arch.asyncio import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    get_cmd,
    walk_cmd,
)



class SnmpError(Exception):
    pass


class SnmpClient():
    def __init__(
        self,
        host: str,
        community: str = "public",
        version: int = 2,
        port: int = 161,
        timeout: float = 1.0,
        retries: int = 2
    ):
        self.host = host
        self.port = port
        self.community = community
        self.version = version
        self.timeout = timeout
        self.retries = retries
        
        self._engine = SnmpEngine()
        self._target: UdpTransportTarget | None = None
    
        if version == 1:
            mp_model = 0
        elif version == 2:
            mp_model = 1
        else:
            raise ValueError(f"Unsupported SNMP version: {version}")

        self._auth = CommunityData(community, mpModel=mp_model)
        
    # ==============================================================
    #               ASYNC версии (скрытые снаружи)
    # ==============================================================
        
    async def ensure_target(self) -> None:
        if self._target is None:
            self._target = await UdpTransportTarget.create(
                (self.host, self.port),
                timeout=self.timeout,
                retries=self.retries
            )


    async def get_async(self, oid: str) -> Any:
        await self._ensure_target()
        
        error_indication, error_status, error_index, var_binds = await get_cmd(
            self._engine,
            self._auth,
            self._target,
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        
        if error_indication:
            raise SnmpError(str(error_indication))
        
        if error_status:
            bad = (
                var_binds[int(error_index) -1][0]
                if error_index
                else "?"
            )
            raise SnmpError(f"{error_status.prettyPrint()} at {bad}")
        
        oid_obj, value = var_binds[0]
        return value.prettyPrint()
        
        
    async def walk_async(self, oid: str) -> Dict[str, Any]:
        await self._ensure_target()
        result: Dict[str, Any] = {}
        
        gen = walk_cmd(
            self._engine,
            self._auth,
            self._target,
            ContextData,
            ObjectType(ObjectIdentity(oid)),
            lexicographicMode=False
        )
        
        async for error_indication, error_status, error_index, var_binds in gen:
            if error_indication:
                raise SnmpError(str(error_indication))
            
            if error_status:
                bad = (
                    var_binds[int(error_index) - 1][0]
                    if error_index 
                    else "?"
                )
                raise SnmpError(f"{error_status.prettyPrint()} at {bad}")
            
            for oid_obj, value in var_binds:
                result[str(oid_obj)] = value.prettyPrint()
         
            return result
         
    # ==============================================================
    #               SYNC версии (блокирующие)
    # ==============================================================
    def get(self, oid: str) -> Any:
        """
        Блокирующий SNMP GET одного OID.
        """
        return asyncio.run(self._get_async(oid))

    def walk(self, oid: str) -> Dict[str, Any]:
        """
        Блокирующий SNMP WALK по поддереву OID.
        """
        return asyncio.run(self._walk_async(oid))

    def get_sysobjectid(self) -> str:
        """
        Хелпер для sysObjectID (1.3.6.1.2.1.1.2.0).
        """
        return str(self.get("1.3.6.1.2.1.1.2.0"))
    
    def close(self) -> None:
        self._engine.close_dispatcher()
        
    