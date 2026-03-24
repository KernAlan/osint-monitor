"""Sanctions feed collector: OFAC SDN, EU, UN consolidated lists."""

from __future__ import annotations

import logging
from datetime import datetime

import requests
from lxml import etree

from osint_monitor.collectors.base import BaseCollector
from osint_monitor.core.models import RawItemModel

logger = logging.getLogger(__name__)

# Public, free, no API key required
SANCTIONS_FEEDS = {
    "OFAC SDN": {
        "url": "https://www.treasury.gov/ofac/downloads/sdn.xml",
        "parser": "_parse_ofac",
    },
    "UN Consolidated": {
        "url": "https://scsanctions.un.org/resources/xml/en/consolidated.xml",
        "parser": "_parse_un",
    },
}


class SanctionsCollector(BaseCollector):
    """Collects from sanctions XML feeds (OFAC, EU, UN)."""

    def __init__(self, feed_name: str = "OFAC SDN", **kwargs):
        feed = SANCTIONS_FEEDS.get(feed_name, SANCTIONS_FEEDS["OFAC SDN"])
        self._parser_name = feed["parser"]
        super().__init__(
            name=feed_name,
            source_type="sanctions",
            url=feed["url"],
            **kwargs,
        )

    def collect(self) -> list[RawItemModel]:
        try:
            resp = requests.get(self.url, timeout=60)
            resp.raise_for_status()
            parser = getattr(self, self._parser_name)
            items = parser(resp.content)
            print(f"  [ok] {self.name}: {len(items)} entries")
            return items
        except Exception as e:
            print(f"  [err] {self.name}: {e}")
            return []

    def _parse_ofac(self, content: bytes) -> list[RawItemModel]:
        """Parse OFAC SDN XML."""
        items = []
        try:
            root = etree.fromstring(content)
            ns = {"sdn": root.nsmap.get(None, "")}

            for entry in root.findall(".//sdnEntry", namespaces={"sdn": ns.get("sdn", "")} if ns.get("sdn") else None):
                if entry is None:
                    continue

                # Try without namespace first, then with
                uid_el = entry.find("uid") or entry.find("{%s}uid" % ns.get("sdn", ""))
                first_el = entry.find("firstName") or entry.find("{%s}firstName" % ns.get("sdn", ""))
                last_el = entry.find("lastName") or entry.find("{%s}lastName" % ns.get("sdn", ""))
                type_el = entry.find("sdnType") or entry.find("{%s}sdnType" % ns.get("sdn", ""))
                program_el = entry.find(".//program") or entry.find(".//{%s}program" % ns.get("sdn", ""))

                uid = uid_el.text if uid_el is not None else ""
                first = first_el.text if first_el is not None else ""
                last = last_el.text if last_el is not None else ""
                sdn_type = type_el.text if type_el is not None else ""
                program = program_el.text if program_el is not None else ""

                name = f"{first} {last}".strip() or uid
                if not name:
                    continue

                items.append(RawItemModel(
                    title=f"OFAC SDN: {name}",
                    content=f"Type: {sdn_type}. Program: {program}. UID: {uid}",
                    url=f"https://sanctionssearch.ofac.treas.gov/Details.aspx?id={uid}",
                    source_name=self.name,
                    external_id=f"ofac_{uid}",
                    fetched_at=datetime.utcnow(),
                ))
        except Exception as e:
            logger.error(f"OFAC parse error: {e}")

        return items[:self.max_items]

    def _parse_un(self, content: bytes) -> list[RawItemModel]:
        """Parse UN consolidated sanctions XML."""
        items = []
        try:
            root = etree.fromstring(content)

            for individual in root.findall(".//INDIVIDUAL"):
                dataid = individual.findtext("DATAID", "")
                first = individual.findtext("FIRST_NAME", "")
                second = individual.findtext("SECOND_NAME", "")
                third = individual.findtext("THIRD_NAME", "")
                name = " ".join(filter(None, [first, second, third]))
                listed_on = individual.findtext("LISTED_ON", "")
                comments = individual.findtext("COMMENTS1", "")

                if not name:
                    continue

                items.append(RawItemModel(
                    title=f"UN Sanctions: {name}",
                    content=f"Listed: {listed_on}. {comments[:500]}",
                    url=f"https://www.un.org/securitycouncil/sanctions/information",
                    source_name=self.name,
                    external_id=f"un_{dataid}",
                    fetched_at=datetime.utcnow(),
                ))

            for entity in root.findall(".//ENTITY"):
                dataid = entity.findtext("DATAID", "")
                name = entity.findtext("FIRST_NAME", "")
                listed_on = entity.findtext("LISTED_ON", "")
                comments = entity.findtext("COMMENTS1", "")

                if not name:
                    continue

                items.append(RawItemModel(
                    title=f"UN Sanctions: {name}",
                    content=f"Listed: {listed_on}. {comments[:500]}",
                    url=f"https://www.un.org/securitycouncil/sanctions/information",
                    source_name=self.name,
                    external_id=f"un_{dataid}",
                    fetched_at=datetime.utcnow(),
                ))
        except Exception as e:
            logger.error(f"UN parse error: {e}")

        return items[:self.max_items]
