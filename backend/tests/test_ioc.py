from app.ioc import classify, defang, extract, is_public_ip, refang, summarise

SYSLOG = """Jan 12 09:22:11 fw01 kernel: DROP IN=eth0 SRC=185.220.101.34 DST=10.0.0.5 PROTO=TCP SPT=51234 DPT=443
Jan 12 09:22:14 proxy01 squid[882]: CONNECT hxxp://malicious-update[.]top/beacon.bin 200
Jan 12 09:23:02 edr01 alert: sha256=9f2c4a1b8e7d6c5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f
Jan 12 09:24:44 mail01: sender=payroll@totally-legit-hr[.]ru subject="Invoice"
"""


def test_extracts_typed_indicators_from_syslog():
    found = {i.type: i.value for i in extract(SYSLOG)}
    assert found["ip"] == "185.220.101.34"
    assert found["domain"] in ("malicious-update.top", "totally-legit-hr.ru")
    assert found["url"] == "http://malicious-update.top/beacon.bin"
    assert found["hash"].startswith("9f2c4a1b")
    assert found["email"] == "payroll@totally-legit-hr.ru"


def test_private_and_reserved_addresses_are_dropped():
    values = [i.value for i in extract("10.0.0.5 192.168.1.1 127.0.0.1 169.254.1.1 8.8.8.8")]
    assert values == ["8.8.8.8"]


def test_filenames_and_versions_are_not_domains():
    values = [i.value for i in extract("svchost.exe loaded v1.2.3 from update.log")]
    assert values == []


def test_defanged_input_is_refanged():
    assert refang("1.2.3[.]4") == "1.2.3.4"
    assert refang("hxxps://evil(.)com") == "https://evil.com"
    assert defang("http://evil.com") == "hxxp://evil[.]com"


def test_json_alert_export_is_parsed():
    payload = (
        '{"Event":{"EventID":4624,"src_ip":"45.155.205.233",'
        '"hashes":"SHA256=44d88612fea8a8f36de82e1278abb02f44d88612fea8a8f36de82e1278abb02f",'
        '"url":"http://drop.example.co/win.exe"}}'
    )
    found = {i.type for i in extract(payload)}
    assert {"ip", "url", "hash"} <= found


def test_classify_and_helpers():
    assert classify("8.8.8.8") == "ip"
    assert classify("192.168.0.1") is None
    assert classify("CVE-2021-44228") == "cve"
    assert classify("d41d8cd98f00b204e9800998ecf8427e") == "hash"
    assert classify("not an ioc") is None
    assert is_public_ip("1.1.1.1") and not is_public_ip("172.16.0.1")


def test_deduplication_and_limit():
    text = "8.8.8.8 8.8.8.8 1.1.1.1 9.9.9.9"
    assert len(extract(text)) == 3
    assert len(extract(text, limit=2)) == 2
    assert summarise(extract(text)) == {"ip": 3}


def test_url_host_is_extracted_as_its_own_indicator():
    values = {i.value for i in extract("https://cdn.bad-host.io/payload?id=1")}
    assert "cdn.bad-host.io" in values
