from functools import lru_cache
from pathlib import Path
from string import Template


FRAGMENTS = Path(__file__).resolve().parent / 'templates' / 'fragments'


@lru_cache(maxsize=None)
def _load_fragment(name):
    return Template((FRAGMENTS / f'{name}.html').read_text(encoding='utf-8'))


def fragment(name, **values):
    """Fill a markup fragment using the dashboard's existing formatted values."""
    return _load_fragment(name).substitute(values)
