"""Adding a target creates a host and, usually, a web app: both must accept the same cohorts."""
from typing import Literal, Union, get_args, get_origin

from targets.asset_router import HostTargetCreate
from targets.router import TargetCreate


def _choices(model, field):
    """The Literal values a field accepts, through an Optional wrapper if present."""
    annotation = model.model_fields[field].annotation
    parts = get_args(annotation) if get_origin(annotation) is Union else (annotation,)
    return {value for part in parts if get_origin(part) is Literal for value in get_args(part)}


def test_host_targets_accept_every_cohort_a_web_target_accepts():
    web = _choices(TargetCreate, 'cohort')
    host = _choices(HostTargetCreate, 'environment')
    assert {'production', 'staging', 'lab', 'demo', 'calibration', 'internal'} <= web
    assert web <= host
    assert HostTargetCreate(locator='calibration.example.test', environment='calibration').environment == 'calibration'
