import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from lab import Lab, spine_leaf  # noqa: E402


def pytest_addoption(parser):
    parser.addoption("--nbgpd", default=os.environ.get("NBGPD", "build/nbgpd"))


@pytest.fixture(scope="session")
def nbgpd(request):
    path = os.path.abspath(request.config.getoption("--nbgpd"))
    assert os.access(path, os.X_OK), f"{path} not built"
    if os.path.exists("/run/nbgp") is False or os.geteuid() != 0:
        pytest.exit("run inside scripts/run.sh (needs the private namespaces)")
    return path


@pytest.fixture(scope="module")
def fabric(nbgpd):
    """The 2-spine / 4-leaf mixed fabric, converged."""
    lab = Lab(spine_leaf(), nbgpd)
    lab.build()
    lab.start()
    try:
        lab.wait(lab.all_established, timeout=30, what="all sessions Established")
        lab.wait(lambda: all(lab.rib(n) == lab.expected_rib(n) for n in lab.nodes), timeout=15,
                 what="all tables converged")
        yield lab
    finally:
        lab.stop()
