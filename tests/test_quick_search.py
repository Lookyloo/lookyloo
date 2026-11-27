from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import Mock

from lookyloo.lookyloo import Lookyloo


class FakeCapture:
    def __init__(self, searchable_text: str, *, error: bool = False) -> None:
        self.searchable_text = searchable_text
        self.error = error

    def search(self, query: str) -> bool:
        return query in self.searchable_text


def test_quick_search_captures_returns_matches_per_query() -> None:
    captures = [
        FakeCapture("https://example.com/ https://shared.test/"),
        FakeCapture("https://other.test/"),
        FakeCapture("https://example.com/error/", error=True),
    ]
    sorted_capture_cache = Mock(return_value=captures)
    lookyloo = SimpleNamespace(
        time_delta_on_index=timedelta(days=1),
        sorted_capture_cache=sorted_capture_cache,
    )

    results = Lookyloo.quick_search_captures(
        lookyloo, ["example.com", "other.test", "example.com", "  "]
    )

    assert list(results) == ["example.com", "other.test"]
    assert results["example.com"] == [captures[0]]
    assert results["other.test"] == [captures[1]]
    sorted_capture_cache.assert_called_once()
    assert sorted_capture_cache.call_args.kwargs["public"] is True
    assert sorted_capture_cache.call_args.kwargs["cached_captures_only"] is True


def test_quick_search_captures_empty_queries_do_not_load_cache() -> None:
    sorted_capture_cache = Mock()
    lookyloo = SimpleNamespace(
        time_delta_on_index=timedelta(days=1),
        sorted_capture_cache=sorted_capture_cache,
    )

    assert Lookyloo.quick_search_captures(lookyloo, ["", "  "]) == {}
    sorted_capture_cache.assert_not_called()
