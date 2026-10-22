# Third-party test configurations

Real-world FortiGate configurations used only as parser test input.

| File | Source | Licence |
| --- | --- | --- |
| `azure_fg100d_5.4.conf` | FortiGate-100D (hardware), FortiOS 5.4, from [Azure VPN config samples](https://github.com/Azure/Azure-vpn-config-samples/tree/master/Fortinet/Current) | published by Microsoft as a sample |
| `fortios_xutils_vm_6.2_multivdom.txt` | FortiGate-VM64, FortiOS 6.2.3, multi-VDOM, from [fortios-xutils](https://github.com/ssato/fortios-xutils) `tests/res/show_configs/fortigate_cli_show_sample_1.txt` | MIT, Copyright (c) 2020 Satoru SATOH |
| `batfish/*.conf` | Edge-case snippets from [Batfish](https://github.com/batfish/batfish) `projects/batfish/src/test/resources/org/batfish/grammar/fortios/testconfigs` | Apache-2.0, Copyright Intentionet / Batfish contributors |

The `fg100f_hq_multivdom.conf` and `fg60f_branch1.conf` files one level up
were written for this project and contain no real data.
