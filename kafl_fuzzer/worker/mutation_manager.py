from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.worker.syscall_manager import *

import random
import json


class Arg:
    def __init__ (self, arg_type):
        self.arg_type = arg_type
        self.kind = None
        self.val = None

        # for ptr
        self.size = None

        # for struct
        self.offset = None

        # for resource
        self.id = None

        # for array
        self.count = None
        self.width = None



class Syscall:
    def __init__(self, name, sysnum, argnum, syscall_type):
        self.name = name
        self.sysnum = sysnum
        self.argnum = argnum
        self.syscall_type = syscall_type
        self.args = {} # "arg1" : Arg()
        self.idx = 0


    def add_arg(self, arg_key : str, arg : Arg):
        self.args[arg_key] = arg


class Prog:
    def __init__(self):
        #self.resource_usage = {} # detailed 구조 미정
        self.syscalls = [] # List[Syscall]

    def get_resources_upto(self, index: int) -> list:
        generated_resources = list()

        upto = min(index, len(self.syscalls))
        cnt = 1

        for syscall in self.syscalls:
            resources = syscall.syscall_type.resource_inout.get("out")
            for resource in resources :
                generated_resources.append(resource)

            cnt += 1
            if cnt > upto : break


        return generated_resources

    def serialize_arg(self, arg) -> dict:
        arg_json = {}
        arg_json["kind"] = arg.kind

        if arg.kind == "retval" or arg.kind == "rsc":
            arg_json["id"] = arg.id

        elif arg.kind == "string" :
            arg_json["val"] = arg.val

        elif arg.kind == "qword" or arg.kind == "dword" or arg.kind == "word" or arg.kind == "byte":
            arg_json["val"] = arg.val

        elif arg.kind == "ptr" :
            arg_json["size"] = arg.size
            arg_json["val"] = self.serialize_arg(arg.val)

        elif arg.kind == "struct" :
            fields = list()

            for field in arg.val:
                field_json = self.serialize_arg(field)
                field_json["offset"] = field.offset
                fields.append(field_json)
            arg_json["val"] = fields

        elif arg.kind == "array" :
            arg_json["count"] = arg.count
            arg_json["width"] = arg.width
            arg_json["val"] = self.serialize_arg(arg.val)

        return arg_json


    def serialize_syscall(self) -> list:
        syscall_list = []
        syscall_index = 1
        for syscall in self.syscalls:

            syscall_json = {
                "name": syscall.name,
                "sysnum" : syscall.sysnum,
                "argnum" : syscall.argnum,
                "idx" : syscall_index
            }

            syscall_args = syscall.args
            for i in range(1, syscall.argnum + 1) :
                arg = syscall_args[f"arg{i}"]
                syscall_json[f"arg{i}"] = self.serialize_arg(arg)

            syscall_list.append(syscall_json)
            syscall_index += 1
        return syscall_list

    def to_testcase(self):
        self.repair_syscall_dependencies()

        tc = self.serialize_syscall()
        return tc

    def get_created_resource_ids_upto(self, resource_types, idx):
        id_map = dict()
        cnt = 1
        resources = self.get_resources_upto(idx)
        for resource in resources:
            if resource not in id_map:
                    id_map[resource] = []

            id_map[resource].append(cnt)
            cnt += 1

        for resource_type in resource_types:
            if id_map.get(resource_type) == None :
                continue
            else:
                return id_map[resource_type]

    def _repair_arg(self, syscall_args, arg, syscall_idx, parent = None ) -> int:

        if arg.kind == "qword" or arg.kind == "dword" or arg.kind == "word" or arg.kind == "byte":
            width_map = {
                "byte" : 1,
                "word" : 2,
                "dword" : 4,
                "qword" : 8
            }

            return width_map.get(arg.kind)

        elif arg.kind == "funcptr":
            return 8

        elif arg.kind == "string":
            return 256

        elif arg.kind == "ptr":
            arg.size = self._repair_arg(syscall_args, arg.val, syscall_idx)
            return 8

        elif arg.kind == "struct":
            total_size = 0
            for field in arg.val :
                size = self._repair_arg(syscall_args, field, syscall_idx, arg)
                total_size += size
            return total_size

        elif arg.kind == "array":
            array_size_info = arg.arg_type.array_size_info
            countkind = arg.arg_type.countkind
            size = 0

            array_kind = array_size_info.get("kind")
            if array_kind == "adjacentfield":
                offset = array_size_info.get("offset")

                for field in parent.val:
                    if field.offset == offset:
                        size = field.val


            elif array_kind == "argfield":
                arg_idx = array_size_info.get("idx")
                offset_list = array_size_info.get("offset")


                if len(offset_list) != 0 :
                    offset = offset_list[0]

                    ref_arg =syscall_args[f"arg{arg_idx}"].val
                    if ref_arg.kind == "struct":
                        size = ref_arg.val[offset].val
                    elif ref_arg.kind == "array":
                        size = ref_arg.val.val
                    else: # scalar
                        size = ref_arg.val

                else :
                    size = syscall_args[f"arg{arg_idx}"].val

            if countkind == "elem" :
                arg.count = size
            elif countkind == "byte" :
                arg.count = int(size / arg.width)

            self._repair_arg(syscall_args, arg.val, syscall_idx)
            return arg.count * arg.width

        elif arg.kind == "rsc" or arg.kind == "retval":
            resource_types = list(arg.arg_type.rsc_type)
            resource_ids = self.get_created_resource_ids_upto(resource_types, syscall_idx)

            if resource_ids == None :
                arg.kind = "dword"
                arg.val = 0
            else:
                resource_id = random.choice(resource_ids)

                arg.id = resource_id

            return 8
        else :
            print("arg.kind = ", arg.kind)
            return


    def repair_syscall_dependencies(self):
        syscall_idx = 1
        for syscall in self.syscalls:
            for i in range(1, syscall.argnum + 1):
                arg_key = f"arg{i}"
                arg = syscall.args.get(arg_key)
                self._repair_arg(syscall.args, arg, syscall_idx)
            syscall_idx += 1






class MutationManager:
    def __init__(self, syscall_manager):
        self.syscall_manager = syscall_manager

    def add_call(self, prog, create_only=False, idx=-1):
        syscall_len = len(prog.syscalls) if idx == -1 else idx

        if create_only:
            self._add_resource_creation_call(prog, syscall_len)
        else:
            self._add_random_call(prog, syscall_len)

    def _add_resource_creation_call(self, prog, syscall_len):
        resources = list(self.syscall_manager.syscall_dependency_map["dependent"].keys())
        used_resources_in_prog = set(prog.get_resources_upto(syscall_len))

        while resources:
            resource = random.choice(resources)
            rsc_create_syscalls = self.syscall_manager.syscall_dependency_map["dependent"][resource]["out"]
            rsc_create_syscall = random.choice(rsc_create_syscalls)

            type_of_rsc_create_syscall = self.syscall_manager.syscall_types[rsc_create_syscall]
            required_resources = type_of_rsc_create_syscall.resource_inout["in"]
            missing_resources = required_resources - used_resources_in_prog


            if not missing_resources or resource in required_resources :
                syscall = self.to_syscall_from_name(rsc_create_syscall)
                prog.syscalls.append(syscall)
                return

            resources.remove(resource)

    def _add_random_call(self, prog, syscall_len):
        rand_num = random.randint(0, 99)
        if rand_num < 30:  # 리소스 생성
            self._add_resource_creation_call(prog, syscall_len)
        elif rand_num < 70:  # 리소스 사용
            self._add_resource_usage_call(prog, syscall_len)
        else:  # 독립적인 syscall 추가
            self._add_independent_call(prog)

    def _add_resource_usage_call(self, prog, syscall_len):
        used_resources_in_prog = set(prog.get_resources_upto(syscall_len))

        if not used_resources_in_prog:
            return

        resource = random.choice(list(used_resources_in_prog))
        syscalls_using_rsc = self.syscall_manager.syscall_dependency_map["dependent"][resource]["in"]
        syscall_using_rsc = random.choice(syscalls_using_rsc)

        syscall = self.to_syscall_from_name(syscall_using_rsc)
        prog.syscalls.append(syscall)

    def _add_independent_call(self, prog):
        independent_syscalls = self.syscall_manager.syscall_dependency_map["independent"]

        if independent_syscalls:
            syscall_name = random.choice(independent_syscalls)
            syscall = self.to_syscall_from_name(syscall_name)
            prog.syscalls.append(syscall)


    def mutate_arg(self, prog):
        chosen_syscall = random.choice(prog.syscalls)
        argnum = chosen_syscall.argnum

        chosen_arg_idx = random.randint(1, argnum)
        chsoen_arg = chosen_syscall.args[f"arg{chosen_arg_idx}"]
        self._mutate_arg(chsoen_arg)

    def _mutate_arg(self, arg):
        if arg.kind == "dword" or arg.kind == "qword" or arg.kind == "word" or arg.kind == "byte":
            width_map = {
                "byte" : 1,
                "word" : 2,
                "dword" : 4,
                "qword" : 8
            }

            width =  width_map.get(arg.kind)
            arg.val = random.randint(0, (2 ** (width * 4)) - 1)

        elif arg.kind == "ptr" :
            self._mutate_arg(arg.val)
        elif arg.kind == "array" :
            self._mutate_arg(arg.val)
        elif arg.kind == "struct" :
            chosen_field = random.choice(arg.val)
            self._mutate_arg(chosen_field)


    def insert(self,prog):
        syscall_len = len(prog.syscalls)

        if syscall_len > 1:
            insert_idx = random.randint(2, syscall_len)
            self.add_call(prog, idx=insert_idx)



    def to_syscall_from_name(self, syscall_name) -> Syscall:
        syscall_type = self.syscall_manager.syscall_types[syscall_name]

        syscall = Syscall(syscall_name, syscall_type.sysnum, syscall_type.argnum, syscall_type)

        for i in range(1, syscall_type.argnum + 1):
            arg_key = f"arg{i}"
            arg_type = syscall_type.arg_types.get(arg_key)
            arg = self.to_arg_from(arg_type)
            syscall.add_arg(arg_key, arg)
        return syscall


    def to_arg_from(self, arg_type) -> Arg :
        arg = Arg(arg_type)

        type = arg_type.type
        arg.offset = arg_type.offset

        if type == "scalar": # basic case
            width_map = {
                1: "byte",
                2: "word",
                4: "dword",
                8: "qword"
            }

            kind = width_map.get(arg_type.width, "qword")
            arg.kind = kind

            val = random.randint(0, 2**(arg_type.width*4) - 1)
            arg.val = val

        elif type == "resource": # basic case
            if arg_type.inout == "out": # rsc
                arg.kind = "rsc"

            elif arg_type.inout == "in": # retval
                arg.kind = "retval"

        elif type == "funcptr":  # basic case
            arg.kind = "funcptr"

        elif type == "stringw":  # basic case
            arg.kind = "string"
            arg.val = "\\??\\C:\\Temp\\test.txt" # temporary

        elif type == "ptr": # inductive case
            arg.kind = "ptr"
            arg.size = 10 # temporary
            arg.val = self.to_arg_from(arg_type.content)

        elif type == "struct" : # inductive case
            arg.kind = "struct"

            arg.val = []
            for field in arg_type.fields:
                field_arg = self.to_arg_from(field)
                arg.val.append(field_arg)

        elif type == "array": # inductive case
            arg.kind = "array"
            arg.width = arg_type.width
            arg.val = self.to_arg_from(arg_type.content)


        return arg




