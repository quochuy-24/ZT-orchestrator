"""LDAP Client - Query Active Directory for user groups"""

from typing import Optional, List
import ldap3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from shared.logger import get_logger

logger = get_logger(__name__)


class LDAPError(Exception):
    pass


class LDAPClient:
    """LDAP client for Active Directory"""

    def __init__(self):
        self.server_ip = "192.168.29.17"
        self.domain = "lab.local"
        self.username = "Administrator"
        self.password = "Quochuy24@"
        self.base_dn = "DC=lab,DC=local"

    def get_user_groups(self, username: str) -> List[str]:
        """Get AD groups for a user"""
        try:
            # Strip domain prefix if exists (LAB\quochuy -> quochuy)
            if "\\" in username:
                username = username.split("\\")[1]

            server = ldap3.Server(self.server_ip, get_info=ldap3.ALL)
            conn = ldap3.Connection(
                server,
                user=f"{self.username}@{self.domain}",
                password=self.password,
                auto_bind=True
            )

            search_filter = f"(sAMAccountName={username})"
            conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                attributes=["memberOf"]
            )

            if not conn.entries:
                logger.warning("ldap_user_not_found", username=username)
                return []

            member_of = conn.entries[0].memberOf.values if conn.entries[0].memberOf else []

            # Extract group names from DN (CN=Accounting,OU=Groups,DC=lab,DC=local -> Accounting)
            groups = []
            for dn in member_of:
                if dn.startswith("CN="):
                    group_name = dn.split(",")[0].replace("CN=", "")
                    groups.append(group_name)

            logger.info("ldap_user_groups_found", username=username, groups=groups, group_count=len(groups), status="success")
            conn.unbind()
            return groups

        except Exception as e:
            logger.error("ldap_query_failed", username=username, error=str(e), exc_info=True)
            raise LDAPError(f"Failed to query LDAP: {e}")
