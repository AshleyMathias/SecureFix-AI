"""
pytest configuration: clear the lru_cache on get_settings before each test
so environment changes between tests don't bleed through.
"""
import pytest
from utils.config import get_settings


@pytest.fixture(autouse=True)
def clear_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
