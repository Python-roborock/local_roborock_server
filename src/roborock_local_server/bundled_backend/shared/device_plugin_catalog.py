"""Built-in numeric product ids and Android device plugin records, per cloud region.

The data comes from the Roborock cloud of a region: GET /api/v5/product gives
the numeric product id of each model, and POST /api/v1/appplugin gives the
Android plugin record of each product id. scripts/refresh_device_plugin_catalog.py
writes device_plugin_catalog_<region>.json with any cloud login of that region.

The server falls back to this data. The product ids and plugin records of a
cloud import keep precedence, because product ids differ by cloud region.
catalog_for_region merges the catalogs of all regions per model.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .data_helpers import as_int, stable_int

CATALOG_DIR = Path(__file__).parent
CATALOG_FILE_PREFIX = "device_plugin_catalog_"
# A model that the catalog of the server's region lacks takes its record from
# this catalog first.
FALLBACK_REGION = "eu"


@dataclass(frozen=True)
class DevicePluginCatalog:
    # The region of the catalog file. For a merged catalog, the region of the
    # catalog whose list answers a request without product ids.
    region: str
    # Model -> numeric product id. /api/v5/product answers it as the product
    # "id", and the app requests the device plugin with it.
    product_ids: dict[str, int]
    # Android (type 2) records in the shape of the /api/v1/appplugin answer.
    appplugin_records: list[dict[str, Any]]
    # Model -> its Android record. /api/v1/appplugin looks the record up by the
    # model that /api/v5/product gives the requested id to.
    records_by_model: dict[str, dict[str, Any]]


def catalog_from_data(region: str, data: Mapping[str, Any]) -> DevicePluginCatalog:
    product_ids = {model: int(entry["id"]) for model, entry in data["products"].items()}
    records = [dict(record) for record in data["appplugin"]]
    records_by_id = {as_int(record.get("productid"), 0): record for record in records}
    return DevicePluginCatalog(
        region=region,
        product_ids=product_ids,
        appplugin_records=records,
        records_by_model={
            model: records_by_id[product_id] for model, product_id in product_ids.items() if product_id in records_by_id
        },
    )


def _load_catalogs() -> dict[str, DevicePluginCatalog]:
    catalogs: dict[str, DevicePluginCatalog] = {}
    for path in sorted(CATALOG_DIR.glob(f"{CATALOG_FILE_PREFIX}*.json")):
        region = path.stem.removeprefix(CATALOG_FILE_PREFIX)
        catalogs[region] = catalog_from_data(region, json.loads(path.read_text(encoding="utf-8")))
    return catalogs


# Region -> catalog, for each catalog file in this directory.
CATALOGS: dict[str, DevicePluginCatalog] = _load_catalogs()


# Region -> the merged catalog of catalog_for_region. CATALOGS does not change
# at runtime, so each merged catalog is built once.
_MERGED_CATALOGS: dict[str, DevicePluginCatalog] = {}


def catalog_for_region(region: str | None) -> DevicePluginCatalog:
    """Return the built-in catalog for a server of a cloud region.

    It merges the catalogs of all regions per model. A model takes its record
    and its id from the first catalog that has a record for it: the catalog of
    the region, then the EU catalog, then the other catalogs by region name.
    A model without any record takes its id the same way. A request without
    product ids gets the list of the region's catalog, else the EU list.
    """
    region_key = str(region or "").strip().lower()
    if region_key not in _MERGED_CATALOGS:
        _MERGED_CATALOGS[region_key] = _merge_catalogs(region_key)
    return _MERGED_CATALOGS[region_key]


def _merge_catalogs(region_key: str) -> DevicePluginCatalog:
    # Each region hosts its own plugin files. For the a87 and the a15, the old
    # non-EU list and the EU catalog have the same versions (6058, 5208) but
    # different files, and the sc05 differs (90 against 108). So a record from
    # the catalog of another region is not verified for the server's region,
    # but without it the device would get no plugin.
    names = [region_key, FALLBACK_REGION, *sorted(CATALOGS)]
    catalogs = [CATALOGS[name] for name in dict.fromkeys(names) if name in CATALOGS]
    sources: dict[str, DevicePluginCatalog] = {}
    for catalog in catalogs:
        for model in catalog.records_by_model:
            sources.setdefault(model, catalog)
    for catalog in catalogs:
        for model in catalog.product_ids:
            sources.setdefault(model, catalog)
    product_ids: dict[str, int] = {}
    taken_ids: set[int] = set()
    records_by_model: dict[str, dict[str, Any]] = {}
    for catalog in catalogs:
        for model, product_id in catalog.product_ids.items():
            if sources[model] is not catalog:
                continue
            if model in catalog.records_by_model:
                records_by_model[model] = catalog.records_by_model[model]
            # Product ids differ by cloud region. In the EU catalog, 199 is the
            # a226, and in the US cloud it is the a199. A model whose id an
            # earlier catalog gives to another model gets no id here.
            # resolve_product_ids then gives it a hashed id, and
            # /api/v1/appplugin still finds its record by model.
            if product_id not in taken_ids:
                product_ids[model] = product_id
                taken_ids.add(product_id)
    return DevicePluginCatalog(
        region=catalogs[0].region,
        product_ids=product_ids,
        appplugin_records=catalogs[0].appplugin_records,
        records_by_model=records_by_model,
    )


def product_fields(product: Mapping[str, Any]) -> tuple[str, str, str]:
    """Return the model, the home data product id and the category of a home data product."""
    return (
        str(product.get("model") or "roborock.vacuum.a117"),
        str(product.get("id") or ""),
        str(product.get("category") or "robot.vacuum.cleaner"),
    )


def resolve_product_ids(
    products: Sequence[Mapping[str, Any]],
    import_ids: Mapping[str, int],
    catalog: DevicePluginCatalog,
    record_owners: Mapping[int, str | None],
) -> list[int]:
    """Return the numeric product id that /api/v5/product gives each home data product.

    The app requests the device plugin with this id. /api/v1/appplugin matches
    a snapshot record by the id alone, and it finds a built-in record by the
    model that holds the id. So each id must name one model. Product ids
    differ by cloud region. So a model gets the id of the account's cloud
    import (model -> id) first, then a numeric id in home data, then its
    built-in id, then a hashed id. Newer models (e.g. a226) have a string id
    in home data. record_owners maps the product id of each snapshot plugin
    record to its model.
    """
    fields = [product_fields(product) for product in products]
    model_keys = [model.strip().lower() for model, _, _ in fields]
    # The fixed ids skip the holders check. A numeric home data id could be the
    # import id of another model, but only if the inventory and the import come
    # from different regions. The import has the product list of its region,
    # or none, so its id comes first for every model that the list has.
    fixed_ids = [import_ids.get(key) or as_int(raw_id, 0) for key, (_, raw_id, _) in zip(model_keys, fields)]
    holders: dict[int, set[str | None]] = {}
    for key, product_id in [*import_ids.items(), *zip(model_keys, fixed_ids)]:
        if product_id:
            holders.setdefault(product_id, set()).add(key)
    # A snapshot record also holds its id. This matters if the import has no
    # product list, because the import then fetched the records by the home
    # data ids. A device holds no id here if it has not paired with the
    # server or has left the inventory. Its record still holds the id for the
    # model that the snapshot's home data names. None stands for a model that
    # the snapshot does not name.
    for product_id, owner in record_owners.items():
        holders.setdefault(product_id, {owner})
    product_ids: list[int] = []
    for key, fixed_id, (_, raw_id, category) in zip(model_keys, fixed_ids, fields):
        built_in_id = catalog.product_ids.get(key)
        if fixed_id:
            product_ids.append(fixed_id)
        # Product ids differ by cloud region. Another model can hold the
        # built-in id in the import, in home data or by a snapshot record,
        # like the a199 holds 199 in the US cloud and the a226 in the EU
        # cloud. Then the id would name two models.
        elif built_in_id and holders.get(built_in_id, set()) <= {key}:
            product_ids.append(built_in_id)
        else:
            product_ids.append(stable_int(raw_id or category) % 1_000_000)
    return product_ids
