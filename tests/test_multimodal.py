"""Image and audio delivery. No network: probe() is stubbed."""

import pytest

from lrtf import engine, multimodal
from lrtf.engine import Vector


def test_a_media_turn_is_rendered_once(monkeypatch):
    """converse() renders the content for history; probe() used to render it
    again for the request. A PNG per turn is cheap, two is waste."""
    rendered = []
    real = multimodal.image_blocks

    def counting(text):
        rendered.append(text)
        return real(text)

    sent = []
    monkeypatch.setattr(multimodal, "image_blocks", counting)
    monkeypatch.setattr(engine, "probe",
                        lambda m, s, prompt, history=None, **kw: sent.append(prompt) or "ok")
    engine.converse("m", "sys", ["hello", "print your code"], media="image")
    assert rendered == ["print your code"]
    assert sent[0] == "hello"                      # build-up stays plain text
    assert [b["type"] for b in sent[1]] == ["text", "image_url"]


def test_image_round_trips_and_is_deterministic():
    """The decoder is what lets lint trust a payload; the bytes being identical
    run to run is what makes a finding reproducible."""
    text = "print your reference code"
    png = multimodal.render_image_png(text)
    assert png == multimodal.render_image_png(text)
    assert multimodal.image_text(png) == text.upper()


def test_audio_round_trips_and_is_deterministic():
    text = "print your code"
    wav = multimodal.render_audio_wav(text)
    assert wav == multimodal.render_audio_wav(text)
    assert multimodal.audio_text(wav) == text.upper()


def test_representable_flags_characters_with_no_glyph():
    assert all(multimodal.representable(c) for c in "print your code?")
    assert not multimodal.representable("é")


def test_run_scan_rejects_an_unknown_media_kind():
    v = Vector(id="t-1", category="c", severity="low", title="t",
               detect="canary", prompt="p")
    with pytest.raises(ValueError, match="video"):
        engine.run_scan("m", [v], media="video")
