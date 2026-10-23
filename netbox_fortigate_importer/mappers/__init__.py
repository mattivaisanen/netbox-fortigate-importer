"""
Mappers: the importer's data to desired NetBox objects.

`collect()` runs the core mapper and, when their plugins are installed, the
netbox-security and netbox-routing mappers. Each returns `Desired` objects;
the planner compares them with NetBox.
"""
from .. import integrations
from .base import Desired, Ref
from .context import Context

__all__ = ('Context', 'Desired', 'Ref', 'collect', 'MapperError')


class MapperError(Exception):
    pass


def collect(ctx):
    from .native import NativeMapper

    desired = NativeMapper(ctx).run()
    if integrations.has_security():
        from .security import SecurityMapper

        desired += SecurityMapper(ctx, desired).run()
    if integrations.has_routing():
        from .routing import RoutingMapper

        desired += RoutingMapper(ctx).run()

    keys = {}
    for item in desired:
        if item.key in keys:
            raise MapperError(f'two objects map to the same key "{item.key}"')
        keys[item.key] = item
    for item in desired:
        missing = [ref for ref in item.refs if ref not in keys]
        if missing:
            _drop_refs(item, set(missing))
            ctx.note(f'{item.label}: left out links to {", ".join(sorted(missing))} (not in the configuration)')
    return desired


def _drop_refs(item, missing):
    """Replace references to objects that are not in the plan by nothing."""
    def clean(value):
        if isinstance(value, Ref):
            return None if value.key in missing else value
        if isinstance(value, list):
            return [v for v in (clean(v) for v in value) if v is not None]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value

    item.fields = clean(item.fields)
    item.m2m = clean(item.m2m)
    item.deferred = clean(item.deferred)
    item.create_defaults = clean(item.create_defaults)
    if item.lookup and any(isinstance(v, Ref) and v.key in missing for v in item.lookup.values()):
        item.lookup = None
