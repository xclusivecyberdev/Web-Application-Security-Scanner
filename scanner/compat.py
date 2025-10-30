"""Compatibility helpers providing fallbacks for optional third-party dependencies."""

from __future__ import annotations

import sys
import types
import urllib.error
import urllib.request
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# requests fallback
# ---------------------------------------------------------------------------


def _install_requests_fallback() -> types.ModuleType:
    module = types.ModuleType("requests")

    class RequestException(Exception):
        """Base exception used to mimic :mod:`requests` failures."""

    @dataclass
    class _ResponseHeaders:
        _headers: Dict[str, str]

        def __post_init__(self) -> None:  # normalise header keys once
            self._canonical = {key.lower(): value for key, value in self._headers.items()}

        def __contains__(self, item: str) -> bool:
            return item.lower() in self._canonical

        def get(self, item: str, default: Optional[str] = None) -> Optional[str]:
            return self._canonical.get(item.lower(), default)

        def items(self):  # pragma: no cover - only used for debugging
            return self._canonical.items()

    class Response:
        """Minimal HTTP response compatible with :mod:`requests`."""

        def __init__(self, url: str, status_code: int, headers: Dict[str, str], text: str):
            self.url = url
            self.status_code = status_code
            self.headers = _ResponseHeaders(headers)
            self.text = text

        @property
        def ok(self) -> bool:
            return 200 <= self.status_code < 400

    class Session:
        """Very small subset of :class:`requests.Session`."""

        def __init__(self) -> None:
            self.headers: Dict[str, str] = {}

        def get(self, url: str, timeout: Optional[float] = None, **kwargs) -> Response:
            request_headers = dict(self.headers)
            request_headers.update(kwargs.get("headers", {}))
            request = urllib.request.Request(url, headers=request_headers)
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    raw = response.read()
                    content_type = response.headers.get_content_charset() or "utf-8"
                    text = raw.decode(content_type, errors="replace")
                    headers = {key: value for key, value in response.headers.items()}
                    return Response(url, response.getcode(), headers, text)
            except urllib.error.URLError as exc:  # pragma: no cover - depends on network
                raise RequestException(str(exc)) from exc

    module.Session = Session
    module.Response = Response
    module.RequestException = RequestException

    exceptions = types.ModuleType("requests.exceptions")
    exceptions.RequestException = RequestException
    module.exceptions = exceptions

    sys.modules.setdefault("requests", module)
    sys.modules.setdefault("requests.exceptions", exceptions)
    return module


try:  # pragma: no cover - executed when dependency is present
    import requests as _requests
except ModuleNotFoundError:  # pragma: no cover - best-effort fallback
    requests = _install_requests_fallback()
else:
    requests = _requests


# ---------------------------------------------------------------------------
# urllib3 fallback
# ---------------------------------------------------------------------------


def _install_urllib3_fallback() -> types.ModuleType:
    module = types.ModuleType("urllib3")

    class HTTPError(Exception):
        """Raised when the fallback HTTP client encounters an error."""

    class Timeout:
        """Placeholder Timeout object matching urllib3 signature."""

        def __init__(self, total: Optional[float] = None):
            self.total = total

    @dataclass
    class HTTPResponse:
        status: int
        data: bytes
        headers: Dict[str, str]

    class PoolManager:
        def request(
            self,
            method: str,
            url: str,
            timeout: Optional[Timeout] = None,
            retries: bool | int | None = None,
            headers: Optional[Dict[str, str]] = None,
        ) -> HTTPResponse:
            request = urllib.request.Request(url, headers=headers or {}, method=method.upper())
            try:
                with urllib.request.urlopen(request, timeout=getattr(timeout, "total", None)) as response:
                    data = response.read()
                    headers_dict = {key: value for key, value in response.headers.items()}
                    return HTTPResponse(status=response.getcode(), data=data, headers=headers_dict)
            except urllib.error.URLError as exc:  # pragma: no cover - depends on network
                raise HTTPError(str(exc)) from exc

    module.PoolManager = PoolManager
    module.Timeout = Timeout

    exceptions = types.ModuleType("urllib3.exceptions")
    exceptions.HTTPError = HTTPError
    module.exceptions = exceptions

    sys.modules.setdefault("urllib3", module)
    sys.modules.setdefault("urllib3.exceptions", exceptions)
    return module


try:  # pragma: no cover
    import urllib3 as _urllib3
except ModuleNotFoundError:  # pragma: no cover - fallback
    urllib3 = _install_urllib3_fallback()
else:
    urllib3 = _urllib3


# ---------------------------------------------------------------------------
# BeautifulSoup fallback
# ---------------------------------------------------------------------------


def _install_bs4_fallback() -> types.ModuleType:
    module = types.ModuleType("bs4")

    class _Node:
        def __init__(self, name: str, attrs: Optional[Dict[str, str]] = None, parent: Optional["_Node"] = None):
            self.name = name
            self.attrs = attrs or {}
            self.parent = parent
            self.children: List[_Node] = []

        def append(self, node: "_Node") -> None:
            self.children.append(node)

        def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
            return self.attrs.get(key, default)

        def find_all(self, name: Optional[str] = None, attrs: Optional[Dict[str, str]] = None) -> List["_Node"]:
            matches: List[_Node] = []
            for child in self.children:
                if (name is None or child.name == name) and _matches_attrs(child, attrs):
                    matches.append(child)
                matches.extend(child.find_all(name, attrs))
            return matches

    def _matches_attrs(node: _Node, attrs: Optional[Dict[str, str]]) -> bool:
        if not attrs:
            return True
        for key, value in attrs.items():
            if node.attrs.get(key) != value:
                return False
        return True

    class _SoupParser(HTMLParser):
        def __init__(self, root: _Node) -> None:
            super().__init__()
            self.stack: List[_Node] = [root]

        def handle_starttag(self, tag: str, attrs: List[tuple[str, Optional[str]]]) -> None:
            node = _Node(tag, {k: v or "" for k, v in attrs}, self.stack[-1])
            self.stack[-1].append(node)
            self.stack.append(node)

        def handle_endtag(self, tag: str) -> None:
            for index in range(len(self.stack) - 1, 0, -1):
                if self.stack[index].name == tag:
                    del self.stack[index:]
                    break

    class BeautifulSoup(_Node):
        def __init__(self, markup: str, parser: str | None = None):  # noqa: D401 - match signature
            super().__init__("[document]")
            _SoupParser(self).feed(markup)

    module.BeautifulSoup = BeautifulSoup
    sys.modules.setdefault("bs4", module)
    return module


try:  # pragma: no cover
    from bs4 import BeautifulSoup as _BeautifulSoup
except ModuleNotFoundError:  # pragma: no cover - fallback
    bs4_module = _install_bs4_fallback()
    BeautifulSoup = bs4_module.BeautifulSoup
else:
    BeautifulSoup = _BeautifulSoup


__all__ = ["requests", "urllib3", "BeautifulSoup"]
