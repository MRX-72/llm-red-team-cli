"""Image and audio delivery. No network: probe() is stubbed."""

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
