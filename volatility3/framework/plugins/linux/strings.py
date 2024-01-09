# This file is Copyright 2023 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

from typing import Iterable, List, Tuple
import re

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints
from volatility3.framework.layers import scanners
from volatility3.plugins.linux import pslist


class Strings(interfaces.plugins.PluginInterface):
    """Mimics the strings utility."""

    _required_framework_version = (2, 4, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        # create a list of requirements for vmayarascan
        return [
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
        ]

    def _generator(self):
        # filter based on the pid option if provided
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        for task in pslist.PsList.list_tasks(
            context=self.context,
            vmlinux_module_name=self.config["kernel"],
            filter_func=filter_func,
        ):
            # attempt to create a process layer for each task and skip those
            # that cannot (e.g. kernel threads)
            proc_layer_name = task.add_process_layer()
            if not proc_layer_name:
                continue

            # get the proc_layer object from the context
            proc_layer = self.context.layers[proc_layer_name]

            # regex pattern to find all printable strings
            # limited between 8 and 256 chars in length
            string_regex = rb"[ -~]{8,256}"

            # use regex scanner to find all strings
            for offset in proc_layer.scan(
                context=self.context,
                scanner=scanners.RegExScanner(string_regex),
            ):
                # read the string from the layer to display the result
                data = proc_layer.read(offset, 256, pad=True)
                # use re to find the match (this is becuase RegExScanner doesn't return the len)
                start, end = re.search(string_regex, data).span()
                result = data[start:end]
                yield 0, (
                    format_hints.Hex(offset),
                    task.tgid,
                    str(result, encoding="latin-1", errors="?"),
                )

    def run(self):
        return renderers.TreeGrid(
            [
                ("Offset", format_hints.Hex),
                ("PID", int),
                ("String", str),
            ],
            self._generator(),
        )
