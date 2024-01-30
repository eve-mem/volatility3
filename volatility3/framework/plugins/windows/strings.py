# This file is Copyright 2019 Volatility Foundation and licensed under the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#

import logging
import re
from typing import Dict, Generator, List, Set, Tuple, Optional

from intervaltree import IntervalTree
from collections import OrderedDict

from volatility3.framework import interfaces, renderers, exceptions, constants
from volatility3.framework.configuration import requirements
from volatility3.framework.layers import intel, resources, linear
from volatility3.framework.renderers import format_hints
from volatility3.plugins.windows import pslist

vollog = logging.getLogger(__name__)


class Strings(interfaces.plugins.PluginInterface):
    """Reads output from the strings command and indicates which process(es) each string belongs to."""

    _version = (2, 0, 0)
    _required_framework_version = (2, 0, 0)
    strings_pattern = re.compile(rb"^(?:\W*)([0-9]+)(?:\W*)(\w[\w\W]+)\n?")

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.PluginRequirement(
                name="pslist", plugin=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process ID to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.URIRequirement(
                name="strings_file", description="Strings file"
            ),
            requirements.BooleanRequirement(
                name="tree",
                description="Use interval tree method for revmap",
                default=False,
                optional=True,
            ),
            requirements.BooleanRequirement(
                name="ordered",
                description="Use an ordered dict method for revmap",
                default=False,
                optional=True,
            ),
        ]
        # TODO: Make URLRequirement that can accept a file address which the framework can open

    def run(self):
        return renderers.TreeGrid(
            [
                ("String", str),
                ("Region", str),
                ("PID", int),
                ("Physical Address", format_hints.Hex),
                ("Virtual Address", format_hints.Hex),
            ],
            self._generator(),
        )

    def _generator(self) -> Generator[Tuple, None, None]:
        """Generates results from a strings file."""
        string_list: List[Tuple[int, bytes]] = []

        # Test strings file format is accurate
        accessor = resources.ResourceAccessor()
        strings_fp = accessor.open(self.config["strings_file"], "rb")
        line = strings_fp.readline()
        count: float = 0
        while line:
            count += 1
            try:
                offset, string = self._parse_line(line)
                string_list.append((offset, string))
            except ValueError:
                vollog.error(f"Line in unrecognized format: line {count}")
            line = strings_fp.readline()
        kernel = self.context.modules[self.config["kernel"]]

        if self.config["tree"] and self.config["ordered"]:
            vollog.warning(
                f"Can't use both tree and ordered methods, using tree instead."
            )

        if self.config["tree"]:
            revmap_tree = self.generate_mapping_tree(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                progress_callback=self._progress_callback,
                pid_list=self.config["pid"],
            )

            last_prog: float = 0
            line_count: float = 0
            num_strings = len(string_list)

            for phys_offset, string in string_list:
                line_count += 1

                mapped_regions = revmap_tree.at(phys_offset)
                if mapped_regions:
                    # at least one process or kernel maps to this area
                    # for each region that maps to this address calculate the
                    # offset of the string, every hit here is a guaranteed match
                    # for the string
                    for mapped_region in mapped_regions:
                        region_offset = phys_offset - mapped_region.begin
                        item = mapped_region.data
                        offset = item.get("offset") + region_offset
                        yield (
                            0,
                            (
                                str(string.strip(), "latin-1"),
                                item.get("region", "Unallocated"),
                                item.get("pid", -1),
                                format_hints.Hex(phys_offset),
                                format_hints.Hex(offset),
                            ),
                        )

                else:
                    # no maps found for this offset
                    yield (
                        0,
                        (
                            str(string.strip(), "latin-1"),
                            "Unallocated",
                            -1,
                            format_hints.Hex(phys_offset),
                            format_hints.Hex(0x00),
                        ),
                    )

            prog = line_count / num_strings * 100
            if round(prog, 1) > last_prog:
                last_prog = round(prog, 1)
                self._progress_callback(prog, "Matching strings in memory")
        elif self.config["ordered"]:
            revmap_ordered = self.generate_mapping_ordered(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                progress_callback=self._progress_callback,
                pid_list=self.config["pid"],
            )

            last_prog: float = 0
            line_count: float = 0
            num_strings = len(string_list)

            # it's important that the string list is ordered so that items can be
            # removed from the revmap_ordered once it's no longer possible for
            # them to contain results
            string_list = sorted(string_list)
            for phys_offset, string in string_list:
                line_count += 1

                keys_to_remove_from_revmap = set()

                string_mapped = False
                for revmap_phys_offset in revmap_ordered:
                    # track the mappins within this round so that
                    # if any need to be compeltely removed they can be.
                    possible_mappings = []

                    for item in revmap_ordered[revmap_phys_offset]:
                        # for each mapping check to see if the phy_offset falls
                        # within this mapping. If it's too small it can be removed
                        # to save it being checked again later
                        mapping_end = revmap_phys_offset + item["size"]

                        # start checking for possible string hits
                        if (revmap_phys_offset <= phys_offset) and (
                            phys_offset <= mapping_end
                        ):
                            # a good mapping, the string fits in thie region
                            possible_mappings.append(item)
                            region_offset = phys_offset - revmap_phys_offset
                            offset = item.get("offset") + region_offset
                            string_mapped = True
                            yield (
                                0,
                                (
                                    str(string.strip(), "latin-1"),
                                    item.get("region", "Unallocated"),
                                    item.get("pid", -1),
                                    format_hints.Hex(phys_offset),
                                    format_hints.Hex(offset),
                                ),
                            )
                        elif (revmap_phys_offset <= phys_offset) and (
                            mapping_end < phys_offset
                        ):
                            # a bad mapping, the string completely after in this region
                            # therefore it does not make the possible_mappings list
                            # since the next string will be located after this one in the
                            # memory image then
                            pass
                        elif revmap_phys_offset <= phys_offset:
                            # while not a hit, it's possible that future strings could
                            # be in this region
                            possible_mappings.append(item)

                    if possible_mappings:
                        revmap_ordered[revmap_phys_offset] = possible_mappings
                    else:
                        # no more mappings here, remove it from the list
                        keys_to_remove_from_revmap.add(revmap_phys_offset)
                        revmap_ordered[revmap_phys_offset] = []

                    if phys_offset < revmap_phys_offset:
                        # if we've gone so far down the list that all the mappings
                        # are now after the offset then there can be no more
                        # valid mappings and we dont need to check. e.g. if the string
                        # is at the start of the memory sample there is no need to
                        # check the mappings for regions that after the string
                        break

                # udpate the revmap_ordered dict for the next string, deleting any keys we can
                for key in keys_to_remove_from_revmap:
                    del revmap_ordered[key]

                # no mappings for this string so it is unallocated
                if not string_mapped:
                    yield (
                        0,
                        (
                            str(string.strip(), "latin-1"),
                            "Unallocated",
                            -1,
                            format_hints.Hex(phys_offset),
                            format_hints.Hex(0x00),
                        ),
                    )

        else:  # use existing revmap method
            #
            revmap = self.generate_mapping(
                self.context,
                kernel.layer_name,
                kernel.symbol_table_name,
                progress_callback=self._progress_callback,
                pid_list=self.config["pid"],
            )

            last_prog: float = 0
            line_count: float = 0
            num_strings = len(string_list)
            for phys_offset, string in string_list:
                line_count += 1

                # calculate the offset for this string within a 4096 page so
                # that this offset can be added to mappings which are all
                # page aligned. This ensures that a string located at phy
                # add 0x1e64cd20 would carry the 0xd20 to the virtual offsets
                # displayed in the plugin output. Without this it would show
                # only the page that the string was found, rather than the
                # actually addr. 0xFFF is 4095 e.g. all lower bits set.
                offset_within_page = phys_offset & 0xFFF

                mapping_entry = revmap.get(
                    phys_offset >> 12,
                    [{"region": "Unallocated", "pid": -1, "offset": 0x00}],
                )

            for item in mapping_entry:
                # Get the full virtual address not just the page start
                # If the string is in unalloacted memory, we set the offset to 0x00
                offset = item.get("offset", 0x00)
                virtual_address = offset + offset_within_page

                yield (
                    0,
                    (
                        str(string.strip(), "latin-1"),
                        item.get("region", "Unallocated"),
                        item.get("pid", -1),
                        format_hints.Hex(phys_offset),
                        format_hints.Hex(virtual_address),
                    ),
                )

            prog = line_count / num_strings * 100
            if round(prog, 1) > last_prog:
                last_prog = round(prog, 1)
                self._progress_callback(prog, "Matching strings in memory")

    def _parse_line(self, line: bytes) -> Tuple[int, bytes]:
        """Parses a single line from a strings file.

        Args:
            line: bytes of the line of a strings file (an offset and a string)

        Returns:
            Tuple of the offset and the string found at that offset
        """

        match = self.strings_pattern.search(line)
        if not match:
            raise ValueError("Strings file contains invalid strings line")
        offset, string = match.group(1, 2)
        return int(offset), string

    def generate_mapping_ordered(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        progress_callback: constants.ProgressCallback = None,
        pid_list: Optional[List[int]] = None,
    ):
        filter = pslist.PsList.create_pid_filter(pid_list)
        revmap_ordered = OrderedDict()
        revmap_unordered = []

        # start with kernel mappings
        layer = context.layers[layer_name]
        min_kernel_addr = 2 ** (layer._maxvirtaddr - 1)
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(
                min_kernel_addr, layer.maximum_address, ignore_errors=True
            ):
                (
                    virt_offset,
                    virt_size,
                    phy_offset,
                    _phy_mapping_size,
                    _phy_layer_name,
                ) = mapval

                revmap_unordered.append(
                    (
                        phy_offset,
                        {
                            "region": "Kerenl",
                            "pid": -1,  # not really needed, just to match orginal revmap method
                            "offset": virt_offset,
                            "size": virt_size,  # need so that we can check later if a string is in this region
                        },
                    )
                )

                if progress_callback:
                    progress_callback(
                        (virt_offset * 100) / layer.maximum_address,
                        f"Creating ordered mapping for kernel",
                    )

        # now process normal processes, ignoring kernel addrs
        for process in pslist.PsList.list_processes(context, layer_name, symbol_table):
            if not filter(process):
                proc_id = "Unknown"
                try:
                    proc_id = process.UniqueProcessId
                    proc_layer_name = process.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug(
                        "Process {}: invalid address {} in layer {}".format(
                            proc_id, excp.invalid_address, excp.layer_name
                        )
                    )
                    continue

                proc_layer = context.layers[proc_layer_name]
                max_proc_addr = (2 ** (proc_layer._maxvirtaddr - 1)) - 1
                if isinstance(proc_layer, linear.LinearlyMappedLayer):
                    for mapval in proc_layer.mapping(
                        0, max_proc_addr, ignore_errors=True
                    ):
                        (
                            virt_offset,
                            virt_size,
                            phy_offset,
                            _phy_mapping_size,
                            _phy_layer_name,
                        ) = mapval

                        revmap_unordered.append(
                            (
                                phy_offset,
                                {
                                    "region": "Process",
                                    "pid": proc_id,  # not really needed, just to match orginal revmap method
                                    "offset": virt_offset,
                                    "size": virt_size,  # need so that we can check later if a string is in this region
                                },
                            )
                        )
                        # FIXME: make the progress for all processes, rather than per-process
                        if progress_callback:
                            progress_callback(
                                (virt_offset * 100) / max_proc_addr,
                                f"Creating ordered mapping for task {proc_id}",
                            )
        # now sort all these mappings to make an ordered dict that can be searched
        # first get sorted list of unique starting phy offsets for all mappings
        if progress_callback:
            progress_callback(0, "Sorting revmap")
        sorted_phy_addrs_list = sorted(
            {phy_addr for phy_addr, _item in (revmap_unordered)}
        )

        # now build the OrderedDict using this list
        progress = 0
        total = len(sorted_phy_addrs_list)
        for key_phy_addr in sorted_phy_addrs_list:
            revmap_ordered[key_phy_addr] = [
                item
                for phy_addr, item in (revmap_unordered)
                if key_phy_addr == phy_addr
            ]
            progress += 1
            if progress_callback:
                progress_callback((progress * 100) / total, "Sorting revmap")

        # return the OrderedDict
        return revmap_ordered

    def generate_mapping_tree(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        progress_callback: constants.ProgressCallback = None,
        pid_list: Optional[List[int]] = None,
    ):
        filter = pslist.PsList.create_pid_filter(pid_list)
        revmap_tree = IntervalTree()

        # start with kernel mappings
        layer = context.layers[layer_name]
        min_kernel_addr = 2 ** (layer._maxvirtaddr - 1)
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(
                min_kernel_addr, layer.maximum_address, ignore_errors=True
            ):
                (
                    virt_offset,
                    _virt_size,
                    phy_offset,
                    phy_mapping_size,
                    _phy_layer_name,
                ) = mapval
                revmap_tree.addi(
                    phy_offset,
                    phy_offset + phy_mapping_size,  # end of
                    {"region": "Kernel", "pid": -1, "offset": virt_offset},
                )
                if progress_callback:
                    progress_callback(
                        (virt_offset * 100) / layer.maximum_address,
                        f"Creating tree mapping for kernel",
                    )

        # now process normal processes, ignoring kernel addrs
        for process in pslist.PsList.list_processes(context, layer_name, symbol_table):
            if not filter(process):
                proc_id = "Unknown"
                try:
                    proc_id = process.UniqueProcessId
                    proc_layer_name = process.add_process_layer()
                except exceptions.InvalidAddressException as excp:
                    vollog.debug(
                        "Process {}: invalid address {} in layer {}".format(
                            proc_id, excp.invalid_address, excp.layer_name
                        )
                    )
                    continue

                proc_layer = context.layers[proc_layer_name]
                max_proc_addr = (2 ** (proc_layer._maxvirtaddr - 1)) - 1
                if isinstance(proc_layer, linear.LinearlyMappedLayer):
                    for mapval in proc_layer.mapping(
                        0, max_proc_addr, ignore_errors=True
                    ):
                        (
                            virt_offset,
                            _virt_size,
                            phy_offset,
                            phy_mapping_size,
                            _phy_layer_name,
                        ) = mapval
                        revmap_tree.addi(
                            phy_offset,
                            phy_offset + phy_mapping_size,
                            {
                                "region": "Process",
                                "pid": proc_id,
                                "offset": virt_offset,
                            },
                        )
                        # FIXME: make the progress for all processes, rather than per-process
                        if progress_callback:
                            progress_callback(
                                (virt_offset * 100) / max_proc_addr,
                                f"Creating tree mapping for task {proc_id}",
                            )
        return revmap_tree

    @classmethod
    def generate_mapping(
        cls,
        context: interfaces.context.ContextInterface,
        layer_name: str,
        symbol_table: str,
        progress_callback: constants.ProgressCallback = None,
        pid_list: Optional[List[int]] = None,
    ) -> Dict[int, Set[Tuple[str, int]]]:
        """Creates a reverse mapping between virtual addresses and physical
        addresses.

        Args:
            context: the context for the method to run against
            layer_name: the layer to map against the string lines
            symbol_table: the name of the symbol table for the provided layer
            progress_callback: an optional callable to display progress
            pid_list: a lit of process IDs to consider when generating the reverse map

        Returns:
            A mapping of virtual offsets to strings and physical offsets
        """
        filter = pslist.PsList.create_pid_filter(pid_list)

        layer = context.layers[layer_name]
        reverse_map: Dict[int, Set[Tuple[str, int]]] = dict()
        if isinstance(layer, intel.Intel):
            # We don't care about errors, we just wanted chunks that map correctly
            for mapval in layer.mapping(0x0, layer.maximum_address, ignore_errors=True):
                (
                    virt_offset,
                    _virt_size,
                    phy_offset,
                    phy_mapping_size,
                    _phy_layer_name,
                ) = mapval

                # for each page within the mapping we need to store the phy_offset and
                # the matching virt_offset
                for offset_to_page_within_mapping in range(0, phy_mapping_size, 0x1000):
                    # calculate the page number for this phy_offset, e.g. the ">> 12"
                    # drops the bits that would address an offset within the page.
                    # This means that all offsets within the same page get the same
                    # physical_page number.
                    physical_page = (
                        phy_mapping_size + offset_to_page_within_mapping
                    ) >> 12

                    # get the existing mappings for this physical page from the
                    # reverse map set.
                    cur_set = reverse_map.get(physical_page, list())

                    # add a mapping for this virtual offset, taking care to add the
                    # offset_to_page_within_mapping to ensure that all pages match correctly.
                    # Without this the 2nd, 3rd etc pages would all incorrectly map to the same
                    # virtual offset.
                    cur_set.append(
                        {
                            "region": "Kernel",
                            "pid": -1,
                            "offset": virt_offset + offset_to_page_within_mapping,
                        }
                    )

                    # store these results back in the reverse_map
                    reverse_map[physical_page] = cur_set
                if progress_callback:
                    progress_callback(
                        (virt_offset * 100) / layer.maximum_address,
                        "Creating reverse kernel map",
                    )

            # TODO: Include kernel modules

            for process in pslist.PsList.list_processes(
                context, layer_name, symbol_table
            ):
                if not filter(process):
                    proc_id = "Unknown"
                    try:
                        proc_id = process.UniqueProcessId
                        proc_layer_name = process.add_process_layer()
                    except exceptions.InvalidAddressException as excp:
                        vollog.debug(
                            "Process {}: invalid address {} in layer {}".format(
                                proc_id, excp.invalid_address, excp.layer_name
                            )
                        )
                        continue

                    proc_layer = context.layers[proc_layer_name]
                    if isinstance(proc_layer, linear.LinearlyMappedLayer):
                        # this follows the same pattern as the kernel mappings above.
                        for mapval in proc_layer.mapping(
                            0x0, proc_layer.maximum_address, ignore_errors=True
                        ):
                            (
                                virt_offset,
                                _virt_size,
                                phy_offset,
                                phy_mapping_size,
                                _phy_layer_name,
                            ) = mapval
                            for offset_to_page_within_mapping in range(
                                0, phy_mapping_size, 0x1000
                            ):
                                physical_page = (
                                    phy_offset + offset_to_page_within_mapping
                                ) >> 12
                                cur_set = reverse_map.get(physical_page, list())
                                cur_set.append(
                                    {
                                        "region": "Process",
                                        "pid": process.UniqueProcessId,
                                        "offset": virt_offset
                                        + offset_to_page_within_mapping,
                                    }
                                )
                                reverse_map[physical_page] = cur_set
                            # FIXME: make the progress for all processes, rather than per-process
                            if progress_callback:
                                progress_callback(
                                    (virt_offset * 100) / proc_layer.maximum_address,
                                    f"Creating mapping for task {process.UniqueProcessId}",
                                )

        return reverse_map
