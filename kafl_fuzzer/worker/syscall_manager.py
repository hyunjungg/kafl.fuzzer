import json
import random
from typing import List, Tuple


class ArgType:
    def __init__(self, type, inout, width, rsc_type, fieldcount, countkind):
        self.type = type
        self.inout = inout
        self.width = width
        self.content = None

        # for ptr
        self.allocated_size = 0

        # for resource
        self.rsc_type = rsc_type

        # for struct
        self.fieldcount = fieldcount
        self.offset = None
        self.fields = []

        # for array
        self.countkind = countkind
        self.size_reference_field = None
        self.array_size_info = {
                                "kind" : str(),
                                "offset" : 0,
                                "idx" : 0,
                                "val" : 0
                                }

class SyscallType:

    def __init__(self, sysnum, argnum):
        '''
            self.arg_types = {
                "arg1" : ArgType(),
                "arg2" : ArgType(),
                ...
            }
        '''
        self.sysnum = sysnum
        self.argnum = argnum
        self.arg_types = {}

        self.resource_inout =  {
                                "in" : set(), # h_event
                                "out" : set() # h_file
                            }

    def add_arg(self, arg_key : str, arg_type : ArgType):
        self.arg_types[arg_key] = arg_type

    def __str__(self):
        return f"SyscallType(sysnum={self.sysnum}, argnum={self.argnum}, arg_types={self.arg_types})"

class SyscallManager:
    def __init__(self):
        """
            {
                "dependent": {
                    "h_file": {
                        "out": ["ntdll!NtCreateFile", "ntdll!NtOpenFile"],  # Syscalls producing the resource
                        "in": ["ntdll!NtClose", "ntdll!NtReadFile"]        # Syscalls consuming the resource
                    }
                },
                "independent": ["ntdll!NtQueryInformationFile", ..]  # Syscalls with no dependencies
            }
        """
        self.syscall_dependency_map = {
                                        "dependent" : dict(),
                                        "independent" : list()
                                       }


        """
         self.syscall_types (dict): Structure to store syscall types
                {
                    "syscall_name": SyscallType(list[ArgType])
                }
        """
        self.syscall_types = dict()

    def build_syscall_dependency_map(self):

        for syscall_name, syscall_type in self.syscall_types.items():
            rsc_in = syscall_type.resource_inout.get("in")
            rsc_out = syscall_type.resource_inout.get("out")

            # If the syscall does not use any resources, add it to the independent list
            if not rsc_in and not rsc_out:
                self.syscall_dependency_map["independent"].append(syscall_name)
                continue

            # If the syscall uses resources, add it to the dependent dictionary
            for rsc in rsc_in:
                if rsc not in self.syscall_dependency_map["dependent"]:
                    self.syscall_dependency_map["dependent"][rsc] = {"in": [], "out": []}
                self.syscall_dependency_map["dependent"][rsc]["in"].append(syscall_name)

            for rsc in rsc_out:
                if rsc not in self.syscall_dependency_map["dependent"]:
                    self.syscall_dependency_map["dependent"][rsc] = {"in": [], "out": []}
                self.syscall_dependency_map["dependent"][rsc]["out"].append(syscall_name)

    def add_syscall_type(self, syscall_name : str, syscall_type : SyscallType):
        self.syscall_types[syscall_name] = syscall_type

    def deserialize_arg_type(self, arg_json : dict, resource_inout) -> Tuple[ArgType, int]:
        type = arg_json.get("type")
        inout = arg_json.get("inout")
        width = arg_json.get("width")
        fieldcount = arg_json.get("fieldcount")
        countkind = arg_json.get("countkind")
        size = arg_json.get("size")
        rsc_type = arg_json.get("rsc_type")
        rsc_type = [rsc_type] if not isinstance(rsc_type, list) else rsc_type

        arg_type = ArgType(type, inout, width, rsc_type, fieldcount, countkind)

        if type == "scalar":
            return arg_type, width

        elif type == "resource":
            if inout == "in":
                resource_inout["in"].update(rsc_type)
            elif inout == "out":
                resource_inout["out"].update(rsc_type)

            return arg_type, 8

        elif type == "funcptr":
            return arg_type, 8

        elif type == "stringw":
            return arg_type, 256

        elif type == "ptr":
            content_json = arg_json.get("content")
            arg_type.content, arg_type.allocated_size = self.deserialize_arg_type(content_json, resource_inout)

            return arg_type, 8

        elif type == "struct":
            fields = arg_json.get("fields")
            total_size = 0
            for field in fields:
                content_json = field.get("content")
                content, size = self.deserialize_arg_type(content_json, resource_inout)
                offset = field.get("offset")
                content.offset = offset
                total_size += size
                arg_type.fields.append(content)

            return arg_type, total_size

        elif type == "array":
            content_json = arg_json.get("content")
            arg_type.content, _ = self.deserialize_arg_type(content_json, resource_inout)

            arg_type.array_size_info["kind"] = size.get("kind")
            arg_type.array_size_info["val"] = size.get("val")
            arg_type.array_size_info["offset"] = size.get("offsets")
            idx = size.get("idx")
            if idx : arg_type.array_size_info["idx"] = idx + 1

            if arg_type.array_size_info["kind"] == "fixed":
                if countkind == "elem" :
                    return arg_type, width * arg_type.array_size_info["val"]
                elif countkind == "byte" :
                    return arg_type, arg_type.array_size_info["val"]

            return arg_type, width

    def deserialize_syscall_types(self, type_json: dict) -> List[SyscallType]:
        syscall_types = dict()
        for name, value in type_json.items():
            sysnum = value["sysnum"]
            argnum = value["argnum"]
            syscall_type = SyscallType(sysnum, argnum)
            resource_inout = {"in" : set(), "out" : set()}
            for i in range(1, argnum + 1):
                arg_key = f"arg{i}"
                arg_type, _ = self.deserialize_arg_type(value[arg_key], resource_inout)
                syscall_type.add_arg(arg_key, arg_type)

            syscall_type.resource_inout = resource_inout
            syscall_types[name] = syscall_type

        return syscall_types

    def load_resourses(self, resources: list):
        for resource in resources:
             self.syscall_dependency_map["dependent"][resource] = {"out": [], "in": []}


    def parse_type_json(self, type_path):
        with open(type_path, "r") as f:
            type_json = json.load(f)

            self.load_resourses(type_json["resources"])

            # Remove the "resources" key
            del type_json["resources"]

            self.syscall_types = self.deserialize_syscall_types(type_json)

            self.build_syscall_dependency_map()