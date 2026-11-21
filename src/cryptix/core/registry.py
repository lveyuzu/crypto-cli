"""Plugin registry and discovery.

Discovery sources (all optional, all failure-isolated):

1. built-ins: every module in ``cryptix.plugins`` is imported and scanned;
2. entry points in the ``cryptix.plugins`` group (installed third-party packages);
3. user plugin files: ``*.py`` in ``$CRYPTIX_PLUGIN_PATH`` (``os.pathsep``-separated)
   or, by default, ``$XDG_CONFIG_HOME/cryptix/plugins`` (``~/.config/cryptix/plugins``).

Set ``CRYPTIX_NO_PLUGINS=1`` to skip sources 2 and 3 (user plugins are arbitrary
local Python code, which is executed on import).

An entry point may refer to a Plugin subclass, a module (all plugin classes
defined in it are registered), an iterable of classes, or a callable
``register(registry)``.
"""

from __future__ import annotations

import difflib
import importlib
import importlib.metadata
import importlib.util
import inspect
import os
import pkgutil
import re
from collections.abc import Iterable
from pathlib import Path
from types import ModuleType
from typing import Any

from cryptix.core.plugin import Category, Cipher, Codec, Decoder, Encoder, Plugin
from cryptix.errors import CryptixError, UnknownPluginError

ENTRY_POINT_GROUP = "cryptix.plugins"
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.+-]*$")


class RegistrationError(CryptixError):
    pass


def user_plugin_dirs() -> list[Path]:
    env = os.environ.get("CRYPTIX_PLUGIN_PATH")
    if env:
        return [Path(p).expanduser() for p in env.split(os.pathsep) if p]
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return [Path(base) / "cryptix" / "plugins"]


class Registry:
    def __init__(self) -> None:
        self._classes: dict[str, type[Plugin]] = {}
        self._aliases: dict[str, str] = {}
        self._sources: dict[str, str] = {}
        self._instances: dict[str, Plugin] = {}
        self.errors: list[tuple[str, str]] = []
        self._discovered: set[str] = set()

    # ---- registration -------------------------------------------------
    def register(self, cls: type[Plugin], *, source: str = "builtin") -> type[Plugin]:
        """Register a plugin class. Re-registering the same class is a no-op."""
        if not (inspect.isclass(cls) and issubclass(cls, Plugin)) or "info" not in cls.__dict__:
            raise RegistrationError(f"{cls!r} is not a Plugin subclass with its own `info`")
        info = cls.info
        if not _NAME_RE.match(info.name):
            raise RegistrationError(f"invalid plugin name {info.name!r} (use [a-z0-9_.+-])")
        existing = self._classes.get(info.name)
        if existing is cls:
            return cls
        if existing is not None:
            raise RegistrationError(
                f"plugin name {info.name!r} already registered by {self._sources[info.name]}"
            )
        both = issubclass(cls, Encoder) and issubclass(cls, Decoder)
        if info.reversible != both:
            raise RegistrationError(
                f"{info.name}: reversible={info.reversible} contradicts its roles {cls.roles()}"
            )
        for alias in info.aliases:
            low = alias.lower()
            if low in self._classes or self._aliases.get(low) not in (None, info.name):
                raise RegistrationError(f"alias {alias!r} of {info.name!r} collides")
        self._classes[info.name] = cls
        self._sources[info.name] = source
        for alias in info.aliases:
            self._aliases[alias.lower()] = info.name
        return cls

    def unregister(self, name: str) -> None:
        canonical = self.resolve_name(name)
        cls = self._classes.pop(canonical)
        self._sources.pop(canonical, None)
        self._instances.pop(canonical, None)
        for alias in cls.info.aliases:
            self._aliases.pop(alias.lower(), None)

    # ---- lookup -------------------------------------------------------
    def resolve_name(self, name: str) -> str:
        low = name.strip().lower()
        if low in self._classes:
            return low
        if low in self._aliases:
            return self._aliases[low]
        candidates = list(self._classes) + list(self._aliases)
        close = difflib.get_close_matches(low, candidates, n=3, cutoff=0.6)
        hint = f" Did you mean: {', '.join(close)}?" if close else ""
        raise UnknownPluginError(f"unknown operation {name!r}.{hint} (see `cryptix list`)")

    def get(self, name: str) -> Plugin:
        canonical = self.resolve_name(name)
        inst = self._instances.get(canonical)
        if inst is None:
            inst = self._instances[canonical] = self._classes[canonical]()
        return inst

    def names(self) -> list[str]:
        return sorted(self._classes)

    def source_of(self, name: str) -> str:
        return self._sources[self.resolve_name(name)]

    def all(
        self, role: type[Plugin] | None = None, category: Category | None = None
    ) -> list[Plugin]:
        out: list[Plugin] = []
        for name in self.names():
            cls = self._classes[name]
            if role is not None and not issubclass(cls, role):
                continue
            if category is not None and cls.info.category is not category:
                continue
            out.append(self.get(name))
        return out

    def decoders(self) -> list[Decoder]:
        return [p for p in self.all(Decoder) if isinstance(p, Decoder)]

    def __contains__(self, name: str) -> bool:
        low = name.strip().lower()
        return low in self._classes or low in self._aliases

    def __len__(self) -> int:
        return len(self._classes)

    # ---- discovery ----------------------------------------------------
    def register_module(self, module: ModuleType, source: str) -> int:
        """Register every plugin class *defined in* ``module``."""
        count = 0
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if cls.__module__ != module.__name__ or not issubclass(cls, Plugin):
                continue
            if "info" not in cls.__dict__ or inspect.isabstract(cls):
                continue
            self.register(cls, source=source)
            count += 1
        return count

    def load_object(self, obj: Any, source: str) -> int:
        """Register whatever an entry point resolved to (see module docstring)."""
        if isinstance(obj, ModuleType):
            return self.register_module(obj, source)
        if inspect.isclass(obj):
            self.register(obj, source=source)
            return 1
        if callable(obj):
            before = len(self)
            obj(self)
            return len(self) - before
        if isinstance(obj, Iterable):
            n = 0
            for item in obj:
                n += self.load_object(item, source)
            return n
        raise RegistrationError(f"cannot register object of type {type(obj).__name__}")

    def discover(
        self,
        *,
        builtins: bool = True,
        entry_points: bool | None = None,
        user_dirs: Iterable[Path] | bool | None = None,
    ) -> None:
        """Run discovery. Each source runs at most once per registry."""
        external = os.environ.get("CRYPTIX_NO_PLUGINS") not in ("1", "true", "yes")
        if entry_points is None:
            entry_points = external
        if user_dirs is None or user_dirs is True:
            user_dirs = user_plugin_dirs() if external else []
        elif user_dirs is False:
            user_dirs = []
        if builtins and "builtins" not in self._discovered:
            self._discovered.add("builtins")
            self._discover_builtins()
        if entry_points and "entry_points" not in self._discovered:
            self._discovered.add("entry_points")
            self._discover_entry_points()
        for d in user_dirs:
            key = f"dir:{d}"
            if key not in self._discovered:
                self._discovered.add(key)
                self._discover_dir(Path(d))

    def _discover_builtins(self) -> None:
        import cryptix.plugins as pkg

        for mod in pkgutil.iter_modules(pkg.__path__):
            if mod.name.startswith("_"):
                continue
            label = f"cryptix.plugins.{mod.name}"
            try:
                self.register_module(importlib.import_module(label), "builtin")
            except Exception as exc:  # a broken builtin must not take the CLI down
                self.errors.append((label, f"{type(exc).__name__}: {exc}"))

    def _discover_entry_points(self) -> None:
        try:
            eps = importlib.metadata.entry_points(group=ENTRY_POINT_GROUP)
        except Exception as exc:  # pragma: no cover - metadata corruption
            self.errors.append(("entry_points", str(exc)))
            return
        for ep in eps:
            label = f"entry-point:{ep.name}"
            try:
                self.load_object(ep.load(), label)
            except Exception as exc:
                self.errors.append((label, f"{type(exc).__name__}: {exc}"))

    def _discover_dir(self, directory: Path) -> None:
        if not directory.is_dir():
            return
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            label = f"user-file:{path}"
            try:
                spec = importlib.util.spec_from_file_location(f"cryptix_user_{path.stem}", path)
                if spec is None or spec.loader is None:
                    raise ImportError("cannot create import spec")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.register_module(module, label)
            except Exception as exc:
                self.errors.append((label, f"{type(exc).__name__}: {exc}"))


_default: Registry | None = None


def get_registry() -> Registry:
    """Process-wide registry with all discovery sources loaded."""
    global _default
    if _default is None:
        _default = Registry()
        _default.discover()
    return _default


__all__ = ["Cipher", "Codec", "Registry", "RegistrationError", "get_registry", "user_plugin_dirs"]
