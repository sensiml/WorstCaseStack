import re
import pprint
import os
import sys
from subprocess import check_output
from argparse import ArgumentParser


class Printable:
    def __repr__(self):
        return (
            "<"
            + type(self).__name__
            + "> "
            + pprint.pformat(vars(self), indent=4, width=1)
        )


class Symbol(Printable):
    pass


class WorstCaseStackParser(object):
    def __init__(
        self,
        rtl_ext_end=".dfinish",
        work_dir=".",  # Working directory
        su_ext=".su",
        obj_ext=".o",
        manual_ext=".msu",
        read_elf_path="readelf",  # You may need to enter the full path here
        stdout_encoding="utf-8",  # System dependant
        dot_c_included=False
    ):
        self.rtl_ext_end = rtl_ext_end
        self.rtl_ext = None  # e.g. '.c.270r.dfinish'. The number '270' will change with gcc version and is auto-detected by the
        # function find_rtl_ext
        self.work_dir = work_dir  # Working directory
        self.su_ext = su_ext
        self.obj_ext = obj_ext
        self.manual_ext = manual_ext
        self.read_elf_path = read_elf_path  # You may need to enter the full path here
        self.stdout_encoding = stdout_encoding  # System dependant
        self.call_graph = {"locals": {}, "globals": {}, "weak": {}}
        self.dot_c_included = dot_c_included

    def read_symbols(self, file):
        from subprocess import check_output

        def to_symbol(read_elf_line):
            v = read_elf_line.split()

            s2 = Symbol()
            s2.value = int(v[1], 16)
            s2.size = int(v[2])
            s2.type = v[3]
            s2.binding = v[4]
            if len(v) >= 8:
                s2.name = v[7]
            else:
                s2.name = ""

            return s2
        print ([self.read_elf_path, "-s", "-W", file])
        output = check_output([self.read_elf_path, "-s", "-W", file]).decode(
            self.stdout_encoding
        )
        lines = output.splitlines()[3:]
        return [to_symbol(line) for line in lines]

    def read_obj(self, tu):
        """
        Reads the file tu.o and gets the binding (global or local) for each function
        :param tu: name of the translation unit (e.g. for main.c, this would be 'main')
        :param call_graph: a object used to store information about each function, results go here
        """
        file = tu if self.dot_c_included else tu[0 : tu.rindex(".")]
        symbols = self.read_symbols(file + self.obj_ext)

        for s in symbols:

            if s.type == "FUNC":
                if s.binding == "GLOBAL":
                    # Check for multiple declarations
                    if (
                        s.name in self.call_graph["globals"]
                        or s.name in self.call_graph["locals"]
                    ):
                        raise Exception("Multiple declarations of {}".format(s.name))
                    self.call_graph["globals"][s.name] = {
                        "tu": tu,
                        "name": s.name,
                        "binding": s.binding,
                    }
                elif s.binding == "LOCAL":
                    # Check for multiple declarations
                    if (
                        s.name in self.call_graph["locals"]
                        and tu in self.call_graph["locals"][s.name]
                    ):
                        raise Exception("Multiple declarations of {}".format(s.name))

                    if s.name not in self.call_graph["locals"]:
                        self.call_graph["locals"][s.name] = {}

                    self.call_graph["locals"][s.name][tu] = {
                        "tu": tu,
                        "name": s.name,
                        "binding": s.binding,
                    }
                elif s.binding == "WEAK":
                    if s.name in self.call_graph["weak"]:
                        raise Exception("Multiple declarations of {}".format(s.name))
                    self.call_graph["weak"][s.name] = {
                        "tu": tu,
                        "name": s.name,
                        "binding": s.binding,
                    }
                else:
                    raise Exception(
                        'Error Unknown Binding "{}" for symbol: {}'.format(
                            s.binding, s.name
                        )
                    )

    def find_fxn(self, tu, fxn):
        """
        Looks up the dictionary associated with the function.
        :param tu: The translation unit in which to look for locals functions
        :param fxn: The function name
        :param call_graph: a object used to store information about each function
        :return: the dictionary for the given function or None
        """

        if fxn in self.call_graph["globals"]:
            return self.call_graph["globals"][fxn]
        else:
            try:
                return self.call_graph["locals"][fxn][tu]
            except KeyError:
                return None

    def find_demangled_fxn(self, tu, fxn):
        """
        Looks up the dictionary associated with the function.
        :param tu: The translation unit in which to look for locals functions
        :param fxn: The function name
        :param call_graph: a object used to store information about each function
        :return: the dictionary for the given function or None
        """
        for f in self.call_graph["globals"].values():
            if "demangledName" in f:
                if f["demangledName"] == fxn:
                    return f
        for f in self.call_graph["locals"].values():
            if tu in f:
                if "demangledName" in f[tu]:
                    if f[tu]["demangledName"] == fxn:
                        return f[tu]
        return None

    def read_rtl(self, tu):
        """
        Read an RTL file and finds callees for each function and if there are calls via function pointer.
        :param tu: the translation unit
        :param call_graph: a object used to store information about each function, results go here
        """

        # Construct A Call Graph
        function = re.compile(
            r"^;; Function (.*) \((\S+), funcdef_no=\d+(, [a-z_]+=\d+)*\)( \([a-z ]+\))?$"
        )
        static_call = re.compile(r'^.*\(call.*"(.*)".*$')
        other_call = re.compile(r"^.*call .*$")

        for line_ in open(tu + self.rtl_ext).readlines():
            m = function.match(line_)
            if m:
                fxn_name = m.group(2)
                fxn_dict2 = self.find_fxn(tu, fxn_name)
                if not fxn_dict2:
                    raise Exception(
                        "Error locating function {} in {}".format(fxn_name, tu)
                    )

                fxn_dict2["demangledName"] = m.group(1)
                fxn_dict2["calls"] = set()
                fxn_dict2["has_ptr_call"] = False
                continue

            m = static_call.match(line_)
            if m:
                fxn_dict2["calls"].add(m.group(1))
                # print("Call:  {0} -> {1}".format(current_fxn, m.group(1)))
                continue

            m = other_call.match(line_)
            if m:
                fxn_dict2["has_ptr_call"] = True
                continue

    def read_su(self, tu):
        """
        Reads the 'local_stack' for each function.  Local stack ignores stack used by callees.
        :param tu: the translation unit
        :param call_graph: a object used to store information about each function, results go here
        :return:
        """

        su_line = re.compile(r'^([^ :]+):([\d]+):([\d]+):(.+)\t(\d+)\t(\S+)$')
        su_line_alt = re.compile(
            r"([^\n:]+):([\d]+):([\d]+):([\w\d\s\*_]+)\s+([\w\d_]+)\(.*\)\t+(\d+)\t+"
        )
        file = tu if self.dot_c_included else tu[0 : tu.rindex(".")]
        print(file+self.su_ext)
        for line in open(file + self.su_ext).readlines():
            print(line)
            m = su_line.match(line)
            if m is None:
                m = su_line_alt.match(line)
                if m:
                    fxn = m.group(5)
                    fxn_dict2 = self.find_demangled_fxn(tu, fxn)
                    fxn_dict2["local_stack"] = int(m.group(6))
                else:
                    print("error parsing line {} in file {}".format(i, file))
            else:
                fxn = m.group(4)
                fxn_dict2 = self.find_demangled_fxn(tu, fxn)
                fxn_dict2["local_stack"] = int(m.group(5))

    def read_manual(self, file):
        """
        reads the manual stack useage files.
        :param file: the file name
        :param call_graph: a object used to store information about each function, results go here
        """

        for line in open(file).readlines():
            fxn, stack_sz = line.split()
            if fxn in self.call_graph:
                raise Exception("Redeclared Function {}".format(fxn))
            self.call_graph["globals"][fxn] = {
                "wcs": int(stack_sz),
                "calls": set(),
                "has_ptr_call": False,
                "local_stack": int(stack_sz),
                "is_manual": True,
                "name": fxn,
                "tu": "#MANUAL",
                "binding": "GLOBAL",
            }

    def validate_all_data(self):
        """
        Check that every entry in the call graph has the followiCould notng fields:
        .calls, .has_ptr_call, .local_stack, .scope, .src_line
        """

        def validate_dict(d):
            if not (
                "calls" in d
                and "has_ptr_call" in d
                and "local_stack" in d
                and "name" in d
                and "tu" in d
            ):
                print("Error data is missing in fxn dictionary {}".format(d))

        # Loop through every global and local function
        # and resolve each call, save results in r_calls
        for fxn_dict2 in self.call_graph["globals"].values():
            validate_dict(fxn_dict2)

        for l_dict in self.call_graph["locals"].values():
            for fxn_dict2 in l_dict.values():
                validate_dict(fxn_dict2)

    def resolve_all_calls(self):
        def resolve_calls(fxn_dict2):
            fxn_dict2["r_calls"] = []
            fxn_dict2["unresolved_calls"] = set()

            for call in fxn_dict2["calls"]:
                call_dict = self.find_fxn(fxn_dict2["tu"], call)
                if call_dict:
                    fxn_dict2["r_calls"].append(call_dict)
                else:
                    fxn_dict2["unresolved_calls"].add(call)

        # Loop through every global and local function
        # and resolve each call, save results in r_calls
        for fxn_dict in self.call_graph["globals"].values():
            resolve_calls(fxn_dict)

        for l_dict in self.call_graph["locals"].values():
            for fxn_dict in l_dict.values():
                resolve_calls(fxn_dict)

    def calc_all_wcs(self):
        def calc_wcs(fxn_dict2, call_graph1, parents):
            """
            Calculates the worst case stack for a fxn that is declared (or called from) in a given file.
            :param parents: This function gets called recursively through the call graph.  If a function has recursion the
            tuple file, fxn will be in the parents stack and everything between the top of the stack and the matching entry
            has recursion.
            :return:
            """

            # If the wcs is already known, then nothing to do
            if "wcs" in fxn_dict2:
                return

            # Check for pointer calls
            if fxn_dict2["has_ptr_call"]:
                fxn_dict2["wcs"] = "unbounded"
                return

            # Check for recursion
            if fxn_dict2 in parents:
                fxn_dict2["wcs"] = "unbounded"
                return

            # Calculate WCS
            call_max = 0
            for call_dict in fxn_dict2["r_calls"]:

                # Calculate the WCS for the called function
                parents.append(fxn_dict2)
                calc_wcs(call_dict, call_graph1, parents)
                parents.pop()

                # If the called function is unbounded, so is this function
                if call_dict["wcs"] == "unbounded":
                    fxn_dict2["wcs"] = "unbounded"
                    return

                # Keep track of the call with the largest stack use
                call_max = max(call_max, call_dict["wcs"])

                # Propagate Unresolved Calls
                for unresolved_call in call_dict["unresolved_calls"]:
                    fxn_dict2["unresolved_calls"].add(unresolved_call)

            fxn_dict2["wcs"] = call_max + fxn_dict2["local_stack"]

        # Loop through every global and local function
        # and resolve each call, save results in r_calls
        for fxn_dict in self.call_graph["globals"].values():
            calc_wcs(fxn_dict, self.call_graph, [])

        for l_dict in self.call_graph["locals"].values():
            for fxn_dict in l_dict.values():
                calc_wcs(fxn_dict, self.call_graph, [])

    def print_all_fxns(self):
        def print_fxn(row_format, fxn_dict2):
            unresolved = fxn_dict2["unresolved_calls"]
            stack = str(fxn_dict2["wcs"])
            if unresolved:
                unresolved_str = "({})".format(" ,".join(unresolved))
                if stack != "unbounded":
                    stack = "unbounded:" + stack
            else:
                unresolved_str = ""

            print(
                row_format.format(
                    fxn_dict2["tu"], fxn_dict2["demangledName"], stack, unresolved_str
                )
            )

        def get_order(val):
            if val == "unbounded":
                return 1
            else:
                return -val

        # Loop through every global and local function
        # and resolve each call, save results in r_calls
        d_list = []
        for fxn_dict in self.call_graph["globals"].values():
            d_list.append(fxn_dict)

        for l_dict in self.call_graph["locals"].values():
            for fxn_dict in l_dict.values():
                d_list.append(fxn_dict)

        d_list.sort(key=lambda item: get_order(item["wcs"]))

        # Calculate table width
        tu_width = max(max([len(d["tu"]) for d in d_list]), 16)
        name_width = max(max([len(d["name"]) for d in d_list]), 13)
        row_format = (
            "{:<"
            + str(tu_width + 2)
            + "}  {:<"
            + str(name_width + 2)
            + "}  {:>14}  {:<17}"
        )

        # Print out the table
        print("")
        print(
            row_format.format(
                "Translation Unit", "Function Name", "Stack", "Unresolved Dependencies"
            )
        )
        for d in d_list:
            print_fxn(row_format, d)

    def find_rtl_ext(self):
        # Find the rtl_extension

        print (self.work_dir)
        for root, directories, filenames in os.walk(self.work_dir):
            for f in filenames:
                if f.endswith(self.rtl_ext_end):
                    self.rtl_ext = f[f[: -len(self.rtl_ext_end)].rindex(".") :]
                    print("rtl_ext = " + self.rtl_ext)
                    return

        print(
            "Could not find any files ending with '.dfinish'.  Check that the script is being run from the correct "
            "directory.  Check that the code was compiled with the correct flags"
        )
        exit(-1)

    def find_files(self, dot_c_included=False):
        tu = []
        manual = []
        all_files = []
        for root, directories, filenames in os.walk("."):
            for filename in filenames:
                all_files.append(os.path.join(root, filename))
        print(all_files)
        files = [f for f in all_files if os.path.isfile(f) and f.endswith(self.rtl_ext)]
        for f in files:
            base = f[0 : -len(self.rtl_ext)]
            short_base = base[0 : base.rindex(".")]
            base_to_use = base if self.dot_c_included else short_base
            print(base_to_use + self.su_ext + " \t" + base_to_use + self.obj_ext)
            if (
                base_to_use + self.su_ext in all_files
                and base_to_use + self.obj_ext in all_files
            ):
                tu.append(base)
                print(
                    "Reading: {}{}, {}{}, {}{}".format(
                        base, self.rtl_ext, short_base, self.su_ext, short_base, self.obj_ext
                    )
                )

        files = [
            f for f in all_files if os.path.isfile(f) and f.endswith(self.manual_ext)
        ]
        for f in files:
            manual.append(f)
            print("Reading: {}".format(f))

        # Print some diagnostic messages
        if not tu:
            print("Could not find any translation units to analyse")
            exit(-1)

        return tu, manual


def main(argv):
    # Constants

    parser = ArgumentParser()

    # Adding optional argument
    parser.add_argument(
        "-s",
        "--su_ext",
        dest="su_ext",
        default=".su",
        help="Stack Usage files extension",
    )

    parser.add_argument(
        "-o",
        "--obj_ext",
        dest="obj_ext",
        default=".o",
        help="Object file extension",
    )

    parser.add_argument(
        "--dot_c_included",
        action="store_true",
        dest="dot_c_included",
        help="Use when object and SU files have <filename.c.su>, rather than <filename.su>",
    )

    parser.add_argument(
        "-r",
        "--read_elf_path",
        dest="read_elf_path",
        default="readelf",
        help="Readelf application to parse files.",
    )

    parser.add_argument(
        "-d",
        "--directory",
        dest="directory",
        default=".",
        help="Base directory for files. Will be recursively scanned.",
    )
    args = parser.parse_args()
    print(args.obj_ext)
    wcs_parser = WorstCaseStackParser(
        rtl_ext_end=".dfinish",
        work_dir=args.directory,
        su_ext=args.su_ext,
        obj_ext=args.obj_ext,
        manual_ext=".msu",
        read_elf_path=args.read_elf_path,
        stdout_encoding="utf-8",
        dot_c_included = args.dot_c_included
    )

    # Find the appropriate RTL extension
    wcs_parser.find_rtl_ext()

    # Find all input files

    tu_list, manual_list = wcs_parser.find_files()

    # Read the input files
    for tu in tu_list:
        wcs_parser.read_obj(tu)  # This must be first

    for fxn in wcs_parser.call_graph["weak"].values():
        if fxn["name"] not in wcs_parser.call_graph["globals"].keys():
            wcs_parser.call_graph["globals"][fxn["name"]] = fxn

    for tu in tu_list:
        wcs_parser.read_rtl(tu)
    for tu in tu_list:
        wcs_parser.read_su(tu)

    # Read manual files
    for m in manual_list:
        wcs_parser.read_manual(m)

    # Validate Data
    wcs_parser.validate_all_data()

    # Resolve All Function Calls
    wcs_parser.resolve_all_calls()

    # Calculate Worst Case Stack For Each Function
    wcs_parser.calc_all_wcs()

    # Print A Nice Message With Each Function and the WCS
    wcs_parser.print_all_fxns()


if __name__ == "__main__":
    main(sys.argv[1:])
