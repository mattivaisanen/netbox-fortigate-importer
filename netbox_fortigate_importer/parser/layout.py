"""
The layout of a parsed configuration: header facts, global settings, VDOMs.

A single-VDOM configuration has everything at the top level. A multi-VDOM
one looks like:

    config vdom             list of VDOMs (empty entries)
    config global           system-wide settings (interfaces, HA, ...)
    config vdom             each VDOM's own settings
        edit root ... next
        edit dmz ... next
    end

The parser merges the two `config vdom` blocks, so here `global` is the
`global` table and each VDOM is an entry of the `vdom` table.
"""
import re
from dataclasses import dataclass, field

from .cli import ParseError, ParseResult, Section

# "FG100D-5.04-FW-build1064-160608", "FGVM64-7.4.0-FW-build2360-230509",
# "FGT60F-7.2.8-FW-build1639-240313"
_VERSION_NEW = re.compile(
    r'^(?P<model>[A-Za-z0-9_]+)-(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?-FW-build(?P<build>\d+)'
)
# "FortiGate-VM64 v6.2.3,build1066,191218 (GA)"
_VERSION_OLD = re.compile(
    r'^(?P<model>.+?) v(?P<major>\d+)\.(?P<minor>\d+)(?:\.(?P<patch>\d+))?,build(?P<build>\d+)'
)

#: FortiOS model codes to marketing names, for the common prefixes.
_MODEL_PREFIXES = (
    ('FGVM', 'FortiGate-VM'),
    ('FGT', 'FortiGate-'),
    ('FWF', 'FortiWiFi-'),
    ('FG', 'FortiGate-'),
)


@dataclass
class ConfigInfo:
    model_code: str = ''
    model_name: str = ''
    major: int | None = None
    minor: int | None = None
    patch: int | None = None
    build: int | None = None
    #: 'nat' or 'transparent'
    opmode: str = ''
    multi_vdom: bool = False
    hostname: str = ''
    alias: str = ''
    serial: str = ''
    is_vm: bool = False

    @property
    def version(self):
        if self.major is None:
            return ''
        parts = [self.major, self.minor if self.minor is not None else 0]
        if self.patch is not None:
            parts.append(self.patch)
        return '.'.join(str(p) for p in parts)

    def as_dict(self):
        return {
            'model_code': self.model_code, 'model_name': self.model_name,
            'version': self.version, 'build': self.build, 'opmode': self.opmode,
            'multi_vdom': self.multi_vdom, 'hostname': self.hostname,
            'alias': self.alias, 'serial': self.serial, 'is_vm': self.is_vm,
        }


@dataclass
class Layout:
    info: ConfigInfo
    global_section: Section
    vdoms: dict[str, Section] = field(default_factory=dict)


def model_name(code):
    """'FG100D' -> 'FortiGate-100D', 'FGVM64' -> 'FortiGate-VM64'."""
    for prefix, name in _MODEL_PREFIXES:
        if code.upper().startswith(prefix):
            rest = code[len(prefix):]
            if prefix == 'FGVM':
                return f'FortiGate-VM{rest}'
            return f'{name}{rest}'
    return code


_SERIAL = re.compile(r'^(FG|FGT|FGVM|FW|FWF|FGR)[A-Z0-9]{8,14}$')


def looks_like_serial(value):
    return bool(value) and bool(_SERIAL.match(value))


def parse_header(header):
    info = ConfigInfo()
    version = header.get('config-version', '')
    first, *rest = version.split(':') if version else ['']
    match = _VERSION_NEW.match(first) or _VERSION_OLD.match(first)
    if match:
        info.model_code = match.group('model').strip()
        info.major = int(match.group('major'))
        minor = int(match.group('minor'))
        # "5.04" means 5.4, "7.4.0" means 7.4.0
        info.minor = minor
        info.patch = int(match.group('patch')) if match.group('patch') else None
        info.build = int(match.group('build'))
    flags = {}
    for item in rest:
        key, _, value = item.partition('=')
        flags[key.strip()] = value.strip()
    # The header's opmode flag doesn't match `system settings` in real
    # backups, so layout() reads the mode from the settings instead.
    info.multi_vdom = flags.get('vdom') == '1'
    if info.model_code:
        if info.model_code.startswith('FortiGate'):
            info.model_name = info.model_code
            info.is_vm = 'VM' in info.model_code
        else:
            info.model_name = model_name(info.model_code)
            info.is_vm = info.model_code.upper().startswith('FGVM') or 'VM' in info.model_code.upper()
    return info


def layout(result: ParseResult):
    """Split a ParseResult into global settings and VDOMs."""
    info = parse_header(result.header)
    root = result.root
    vdom_table = root.tables.get('vdom')
    global_table = root.tables.get('global')
    if vdom_table is not None and global_table is None and vdom_table.entries:
        # A backup of single VDOMs (a VDOM administrator's, or one with VDOM
        # scope). Without the global part (interfaces, HA, hostname) every
        # firewall-wide object would look deleted.
        raise ParseError(
            'This backup has only VDOM settings ({}), not the global part with the interfaces and '
            'hostname. Back up the full configuration (as a global administrator) and upload that '
            'instead.'.format(', '.join(vdom_table.entries)))
    if vdom_table is not None and global_table is not None:
        info.multi_vdom = True
        global_section = global_table
        vdoms = {name: entry for name, entry in vdom_table.entries.items()}
    else:
        info.multi_vdom = False
        global_section = root
        vdoms = {'root': root}

    first_vdom = next(iter(vdoms.values()), Section())
    info.opmode = first_vdom.table('system settings').get('opmode', 'nat') or 'nat'
    system_global = global_section.table('system global')
    info.hostname = system_global.get('hostname', '') or ''
    info.alias = system_global.get('alias', '') or ''
    if looks_like_serial(info.alias):
        info.serial = info.alias
    if not info.hostname:
        info.hostname = info.alias
    return Layout(info=info, global_section=global_section, vdoms=vdoms)
