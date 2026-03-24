"""Tests for osint_monitor.collectors.ais.parse_vessel_mention (pure function)."""

from osint_monitor.collectors.ais import parse_vessel_mention


def test_parse_uss():
    result = parse_vessel_mention("The USS Enterprise, a carrier, transited the strait.")
    assert result is not None
    assert "ship_name" in result
    assert "Enterprise" in result["ship_name"]
    assert result["ship_prefix"] == "USS"
    assert result["navy"] == "United States Navy"


def test_parse_hms():
    result = parse_vessel_mention("HMS Defender, a destroyer, departed Portsmouth.")
    assert result is not None
    assert "ship_name" in result
    assert "Defender" in result["ship_name"]
    assert result["ship_prefix"] == "HMS"
    assert result["navy"] == "Royal Navy"


def test_parse_hull():
    result = parse_vessel_mention("DDG-51 is a guided-missile destroyer.")
    assert result is not None
    assert "hull_number" in result
    assert "DDG" in result["hull_number"]


def test_parse_imo():
    result = parse_vessel_mention("Vessel tracked under IMO 1234567 near Hormuz.")
    assert result is not None
    assert result["imo"] == "1234567"


def test_parse_mmsi():
    result = parse_vessel_mention("AIS signal from MMSI 123456789 detected.")
    assert result is not None
    assert result["mmsi"] == "123456789"


def test_no_vessel():
    result = parse_vessel_mention("The weather is nice today in London.")
    assert result is None
