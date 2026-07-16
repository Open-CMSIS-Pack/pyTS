# Copyright 2026 Arm Limited
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file was created using artificial intelligence.

"""Generate architectural CoreSight register settings for CMSIS trace."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Callable
from typing import cast

from pyts._version import package_version
from pyts.coresight.model import (
    CoreSight,
    DataMatch,
    DataTraceRequest,
    DwtVersion,
    RegisterWrite,
    dwt_version_for_core,
)
from pyts.coresight.v1 import DwtV1CoreSight
from pyts.coresight.v2 import DwtV2CoreSight
from pyts.domain import JsonValue, YamlMapping
from pyts.yaml_io import HexInt


@dataclass(frozen=True)
class Processor:
    """Processor information relevant to architectural trace generation."""

    core: str
    pname: str | None
    dwt_version: DwtVersion | int | None

    def __post_init__(self) -> None:
        """Normalize and validate the DWT version against the core name."""

        if isinstance(self.dwt_version, int) and not isinstance(
            self.dwt_version, DwtVersion
        ):
            object.__setattr__(self, "dwt_version", DwtVersion(self.dwt_version))
        expected = dwt_version_for_core(self.core)
        if self.dwt_version != expected:
            raise ValueError(
                f"DWT version for core {self.core!r} must be "
                f"{expected.value if expected is not None else None}"
            )

    @classmethod
    def from_core(cls, core: str, pname: str | None) -> Processor:
        """Create a processor whose DWT generation is derived from its core."""

        return cls(core=core, pname=pname, dwt_version=dwt_version_for_core(core))

_EVENT_BITS = {
    "CYCCNT": 22,
    "CPICNT": 17,
    "EXCCNT": 18,
    "SLEEPCNT": 19,
    "LSUCNT": 20,
    "FOLDCNT": 21,
}

_PC_SAMPLING_PERIODS: dict[str, tuple[int, int]] = {
    f"{cyctap}*{postpreset}": (cyctap_bit, postpreset - 1)
    for cyctap, cyctap_bit in ((64, 0), (1024, 1))
    for postpreset in range(1, 17)
}


@dataclass(frozen=True)
class FeatureSpec:
    """Static dispatch metadata for one CMSIS trace feature."""

    ref_type: str
    repeated: bool = False


_FEATURE_SPECS = {
    "timestamps": FeatureSpec("dwt"),
    "timesync": FeatureSpec("global_ts"),
    "data": FeatureSpec("dwt", repeated=True),
    "exceptions": FeatureSpec("exception"),
    "events": FeatureSpec("event", repeated=True),
    "itm": FeatureSpec("itm"),
    "pcsampling": FeatureSpec("pcsample"),
    "synchronization": FeatureSpec("dwt", repeated=True),
    "instructions": FeatureSpec("dwt"),
    "tracehalt": FeatureSpec("dwt"),
}

FeatureEncoder = Callable[[JsonValue, CoreSight], list[YamlMapping]]


def processors_from_cbuild(cbuild_run: YamlMapping) -> list[Processor]:
    """Return processor trace models from cbuild-run system resources."""

    resources = cbuild_run.get("system-resources")
    if not isinstance(resources, dict):
        return []
    entries = resources.get("processors")
    if not isinstance(entries, list):
        return []

    processors: list[Processor] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        core = entry.get("core")
        if not isinstance(core, str) or not core:
            continue
        pname = entry.get("pname")
        processors.append(
            Processor.from_core(
                core,
                pname if isinstance(pname, str) and pname else None,
            )
        )
    return processors


def create_coresight(processor: Processor) -> CoreSight | None:
    """Create the architectural CoreSight implementation for a processor."""

    if processor.dwt_version == DwtVersion.V1:
        return DwtV1CoreSight(processor.core)
    if processor.dwt_version == DwtVersion.V2:
        return DwtV2CoreSight(processor.core)
    return None


def generate_ctrace_run(
    ctrace: YamlMapping,
    processors: list[Processor],
) -> YamlMapping:
    """Generate an enriched ctrace-run document and CoreSight settings."""

    root = ctrace.get("ctrace")
    if not isinstance(root, dict):
        raise ValueError("ctrace must be a mapping")
    setups = root.get("setup")
    if not isinstance(setups, list):
        raise ValueError("ctrace.setup must be a list")

    refs: list[YamlMapping] = []
    multi_processor = len(processors) > 1
    implementations: dict[int, CoreSight | None] = {}
    for processor in processors:
        implementation = create_coresight(processor)
        if (
            isinstance(implementation, DwtV1CoreSight)
            and _processor_has_data_match(setups, processor)
        ):
            implementation.reserve_data_match_pair()
        implementations[id(processor)] = implementation

    for setup in setups:
        if not isinstance(setup, dict) or "disable" in setup:
            continue
        selected = _select_processors(setup, processors)
        setup_pname = setup.get("pname")
        prefix = setup_pname if isinstance(setup_pname, str) and setup_pname else None
        for processor in selected:
            ref_pname = processor.pname if multi_processor else None
            refs.extend(
                _setup_refs(
                    setup,
                    prefix,
                    processor,
                    ref_pname,
                    implementations[id(processor)],
                )
            )

    run_root = _hexify_addresses(root)
    run_root = cast(YamlMapping, run_root)
    generated_by = f"pyTS v{package_version()}"
    output_root: YamlMapping = {"generated-by": generated_by}
    output_root.update(run_root)
    output_root["generated-by"] = generated_by
    output_root["ctrace-refs"] = cast(JsonValue, refs)
    return {"ctrace-run": output_root}


def _select_processors(
    setup: YamlMapping,
    processors: list[Processor],
) -> list[Processor]:
    """Select processors targeted by one setup mapping."""

    pname = setup.get("pname")
    if not isinstance(pname, str) or not pname:
        return processors
    selected = [processor for processor in processors if processor.pname == pname]
    if not selected:
        raise ValueError(f"ctrace setup references unknown processor: {pname}")
    return selected


def _processor_has_data_match(
    setups: list[JsonValue],
    processor: Processor,
) -> bool:
    """Return whether a processor has a syntactically valid match request."""

    for setup in setups:
        if not isinstance(setup, dict) or "disable" in setup:
            continue
        pname = setup.get("pname")
        if isinstance(pname, str) and pname and pname != processor.pname:
            continue
        data = setup.get("data")
        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if not isinstance(entry, dict) or "match" not in entry:
                continue
            try:
                DataMatch.from_yaml(entry["match"])
            except ValueError:
                continue
            return True
    return False


def _setup_refs(
    setup: YamlMapping,
    prefix: str | None,
    processor: Processor,
    ref_pname: str | None,
    coresight: CoreSight | None,
) -> list[YamlMapping]:
    """Generate all trace references for one setup and processor."""

    refs: list[YamlMapping] = []
    for feature, spec in _FEATURE_SPECS.items():
        if feature not in setup:
            continue
        value = setup[feature]
        if spec.repeated and isinstance(value, list):
            for index, entry in enumerate(value):
                ref = _feature_ref(
                    feature,
                    entry,
                    f"{feature}#{index}",
                    processor,
                    ref_pname,
                    coresight,
                )
                refs.append(_with_prefix(ref, prefix))
        else:
            ref = _feature_ref(
                feature,
                value,
                feature,
                processor,
                ref_pname,
                coresight,
            )
            refs.append(_with_prefix(ref, prefix))
    return refs


def _with_prefix(ref: YamlMapping, prefix: str | None) -> YamlMapping:
    """Apply an optional setup prefix to a generated reference name."""

    name = ref["ctrace-ref"]
    if prefix is not None:
        ref["ctrace-ref"] = f"{prefix}/{name}"
    return ref


def _feature_ref(
    feature: str,
    value: JsonValue,
    ref_name: str,
    processor: Processor,
    ref_pname: str | None,
    coresight: CoreSight | None,
) -> YamlMapping:
    """Build one feature reference, embedding generation failures as errors."""

    ref: YamlMapping = {"ctrace-ref": ref_name, "type": _feature_type(feature)}
    if ref_pname is not None:
        ref["pname"] = ref_pname
    if coresight is None:
        ref["error"] = f"core {processor.core} has no architectural ITM/DWT trace support"
        return ref

    try:
        regs = _feature_regs(
            feature,
            value,
            coresight,
        )
    except ValueError as error:
        ref["error"] = str(error)
        return ref

    if feature == "data" and isinstance(value, dict):
        symbol_file = value.get("symbol-file")
        address = _integer(value.get("address"))
        if isinstance(symbol_file, str):
            ref["symbol-file"] = symbol_file
        if address is not None:
            ref["symbol-address"] = HexInt(address)
    if regs:
        ref["regs"] = cast(JsonValue, regs)
    return ref


def _feature_type(feature: str) -> str:
    """Return the CMSIS reference type for a feature name."""

    return _FEATURE_SPECS[feature].ref_type


def _feature_regs(
    feature: str,
    value: JsonValue,
    coresight: CoreSight,
) -> list[YamlMapping]:
    """Dispatch a feature value to its register encoder."""

    encoder = _FEATURE_ENCODERS.get(feature)
    if encoder is None:
        raise ValueError(f"{feature} trace register generation is not supported")
    return encoder(value, coresight)


def _itm_regs(value: JsonValue) -> list[YamlMapping]:
    """Generate ITM stimulus-port and privilege register writes."""

    if not isinstance(value, dict):
        raise ValueError("itm must be a mapping")
    enable = _required_u32(value.get("enable"), "itm.enable")
    privileged = _u32(value.get("privileged", 0), "itm.privileged")
    return [
        _reg("ITM_TER0", enable),
        _reg("ITM_TPR", privileged, 0xF),
        _reg("ITM_TCR", 1, 1),
    ]


def _timestamp_regs(value: JsonValue) -> list[YamlMapping]:
    """Generate local timestamp configuration writes."""

    if value is not None and not isinstance(value, dict):
        raise ValueError("timestamps must be an empty node or mapping")
    prescaler = 1 if value is None else value.get("itm-prescaler", 1)
    encodings = {1: 0, 4: 1, 16: 2, 64: 3}
    if not isinstance(prescaler, int) or isinstance(prescaler, bool):
        raise ValueError("timestamps.itm-prescaler must be 1, 4, 16, or 64")
    if prescaler not in encodings:
        raise ValueError("timestamps.itm-prescaler must be 1, 4, 16, or 64")
    tcr = (encodings[prescaler] << 8) | (1 << 1) | 1
    return [_reg("ITM_TCR", tcr, 0x303)]


def _event_regs(value: JsonValue) -> list[YamlMapping]:
    """Generate DWT event-counter trace configuration writes."""

    if not isinstance(value, dict):
        raise ValueError("events entry must contain an event name")
    event_value = value.get("event")
    if not isinstance(event_value, str):
        raise ValueError("events entry must contain an event name")
    event = event_value.upper()
    bit = _EVENT_BITS.get(event)
    if bit is None:
        raise ValueError(f"unsupported DWT event: {value['event']}")
    ctrl = (1 << bit) | (1 if event == "CYCCNT" else 0)
    return _dwt_ctrl_regs(ctrl)


def _synchronization_regs(value: JsonValue) -> list[YamlMapping]:
    """Generate DWT synchronization configuration writes."""

    if not isinstance(value, dict):
        raise ValueError("synchronization entry must contain a period")
    period_value = value.get("period")
    if not isinstance(period_value, str):
        raise ValueError("synchronization entry must contain a period")
    period = period_value.upper().replace("/", "\\")
    encodings = {"DWT\\16M": 0, "DWT\\64M": 1, "DWT\\256M": 2}
    if period == "DWT\\0":
        return [_reg("ITM_TCR", 0, 1 << 2)]
    if period not in encodings:
        raise ValueError(f"unsupported synchronization period: {value['period']}")
    return [
        _reg("DWT_CTRL", encodings[period] << 10, 0xC00),
        _reg("ITM_TCR", (1 << 2) | 1, (1 << 2) | 1),
    ]


def _pc_sampling_regs(value: JsonValue) -> list[YamlMapping]:
    """Generate periodic PC sampling configuration writes."""

    if value is not None and not isinstance(value, dict):
        raise ValueError("pcsampling must be an empty node or mapping")
    if value is None or "period" not in value:
        return [_reg("DWT_CTRL", 0, 1 << 12)]
    period = value["period"]
    if not isinstance(period, str):
        raise ValueError("pcsampling.period must be a CYCTAP*POSTPRESET literal")
    encoding = _PC_SAMPLING_PERIODS.get(period)
    if encoding is None:
        raise ValueError(f"unsupported pcsampling.period: {period}")
    cyctap, postpreset = encoding
    ctrl = (1 << 12) | (cyctap << 9) | (postpreset << 1) | 1
    mask = (1 << 12) | (1 << 9) | (0xF << 1) | 1
    return [_reg("DWT_CTRL", ctrl, mask), *_dwt_forwarding_regs()]


def _data_regs(
    value: JsonValue,
    coresight: CoreSight,
) -> list[YamlMapping]:
    """Validate and encode one data trace request."""

    return coresight.encode_data(DataTraceRequest.from_yaml(value))


def _dwt_ctrl_regs(value: int) -> list[YamlMapping]:
    """Return a masked DWT control write with forwarding enabled."""

    return [_reg("DWT_CTRL", value, value), *_dwt_forwarding_regs()]


def _dwt_forwarding_regs() -> list[YamlMapping]:
    """Return the ITM write that enables DWT packet forwarding."""

    return [_reg("ITM_TCR", (1 << 3) | 1, (1 << 3) | 1)]


def _reg(name: str, value: int, mask: int | None = None) -> YamlMapping:
    """Serialize one register write as a YAML mapping."""

    return RegisterWrite(name, value, mask).to_yaml()


def _hexify_addresses(value: JsonValue) -> JsonValue:
    """Copy a JSON value while marking address fields for hex serialization."""

    if isinstance(value, dict):
        result: YamlMapping = {}
        for key, item in value.items():
            if key == "address":
                address = _integer(item)
                result[key] = HexInt(address) if address is not None else item
            else:
                result[key] = _hexify_addresses(item)
        return result
    if isinstance(value, list):
        return [_hexify_addresses(item) for item in value]
    return value


def _integer(value: JsonValue) -> int | None:
    """Parse an integer scalar while rejecting booleans and invalid strings."""

    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _required_u32(value: JsonValue, name: str) -> int:
    """Parse a required unsigned 32-bit configuration value."""

    parsed = _integer(value)
    if parsed is None:
        raise ValueError(f"{name} is required")
    return _u32(parsed, name)


def _u32(value: JsonValue, name: str) -> int:
    """Parse and range-check an unsigned 32-bit configuration value."""

    parsed = _integer(value)
    if parsed is None or not 0 <= parsed <= 0xFFFFFFFF:
        raise ValueError(f"{name} must be a 32-bit unsigned integer")
    return parsed


def _itm_feature(value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    """Adapt ITM generation to the common feature encoder signature."""

    return _itm_regs(value)


def _timestamp_feature(value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    """Adapt timestamp generation to the common feature encoder signature."""

    return _timestamp_regs(value)


def _exception_feature(_value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    """Generate exception-trace feature writes."""

    return _dwt_ctrl_regs(1 << 16)


def _event_feature(value: JsonValue, _coresight: CoreSight) -> list[YamlMapping]:
    """Adapt event generation to the common feature encoder signature."""

    return _event_regs(value)


def _synchronization_feature(
    value: JsonValue,
    _coresight: CoreSight,
) -> list[YamlMapping]:
    """Adapt synchronization generation to the feature encoder signature."""

    return _synchronization_regs(value)


def _data_feature(value: JsonValue, coresight: CoreSight) -> list[YamlMapping]:
    """Adapt data generation to the common feature encoder signature."""

    return _data_regs(value, coresight)


def _pc_sampling_feature(
    value: JsonValue,
    _coresight: CoreSight,
) -> list[YamlMapping]:
    """Adapt PC sampling generation to the feature encoder signature."""

    return _pc_sampling_regs(value)


_FEATURE_ENCODERS: dict[str, FeatureEncoder] = {
    "itm": _itm_feature,
    "timestamps": _timestamp_feature,
    "exceptions": _exception_feature,
    "events": _event_feature,
    "synchronization": _synchronization_feature,
    "data": _data_feature,
    "pcsampling": _pc_sampling_feature,
}
