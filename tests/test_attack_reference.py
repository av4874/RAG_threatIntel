from threat_digest.attack_reference import is_valid_technique_id


def test_is_valid_technique_id_returns_true_for_real_technique():
    assert is_valid_technique_id("T1190") is True


def test_is_valid_technique_id_returns_false_for_fake_technique():
    assert is_valid_technique_id("T9999") is False


def test_is_valid_technique_id_returns_false_for_empty_string():
    assert is_valid_technique_id("") is False
