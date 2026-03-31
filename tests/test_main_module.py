"""
Test for gitlab_ioc_scanner.__main__ module.

Covers the `python -m gitlab_ioc_scanner` entry point.
"""

from __future__ import annotations

from unittest.mock import patch


class TestMainModule:
    @patch("gitlab_ioc_scanner.cli.main", return_value=0)
    def test_main_module_calls_main(self, mock_main):
        """__main__.py calls main() and passes return to sys.exit."""
        with pytest.raises(SystemExit) as exc:
            import importlib

            import gitlab_ioc_scanner.__main__ as mod

            importlib.reload(mod)
        assert exc.value.code == 0

    @patch("gitlab_ioc_scanner.cli.main", return_value=2)
    def test_main_module_exit_code_propagated(self, mock_main):
        """Exit code from main() is propagated to sys.exit."""
        with pytest.raises(SystemExit) as exc:
            import importlib

            import gitlab_ioc_scanner.__main__ as mod

            importlib.reload(mod)
        assert exc.value.code == 2


import pytest
