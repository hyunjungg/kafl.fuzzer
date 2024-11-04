from kafl_fuzzer.common.rand import rand
from kafl_fuzzer.worker.syscall_manager import Field


import random
import json

class MutationManager:
    def __init__(self, syscall_manager):
        self.syscall_manager = syscall_manager

    def add_call(self, prog, create_only=False):
        """프로그램에 리소스를 생성하는 syscall만 추가"""
        resource = str()
        if create_only:
            # resources_usage_desc에서 리소스를 생성하는 syscall 무작위로 선택
            resources = self.syscall_manager.get_resources_desc()
            resource = random.choice(list(resources.keys()))
            resource_creating_syscalls = self.syscall_manager.get_resource_create_syscalls(resource)
            new_call = random.choice(resource_creating_syscalls)  # 무작위로 syscall 선택

            if resource not in prog.resources:
                prog.resources[resource] = resources[resource]
        else:
            rand_num = random.randint(0, 99)

            if rand_num < 40: # resource create
                resources = self.syscall_manager.get_resources_desc()
                resource = random.choice(list(resources.keys()))
                resource_creating_syscalls = self.syscall_manager.get_resource_create_syscalls(resource)
                new_call = random.choice(resource_creating_syscalls)  # 무작위로 syscall 선택

                if resource not in prog.resources:
                    prog.resources[resource] = resources[resource]
            else: # resource use
                resource = random.choice(list(prog.resources.keys()))
                resource_using_syscalls = self.syscall_manager.get_resource_use_syscalls(resource)
                new_call = random.choice(resource_using_syscalls)


        prog.calls.append(new_call)

    def mutate_arg(self, prog):
        if not prog.calls:
            return
        chosen_syscall = random.choice(prog.calls)

        chosen_arg = random.choice(chosen_syscall.args)
        self._mutate_field(chosen_arg)


    def _mutate_field(self, field):
        if field.type_ == "scalar" and field.width:
            field.value = random.randint(0, (2 ** (field.width * 4)) - 1)

        elif field.type_ == "ptr" and field.content:
            self._mutate_field(field.content)

        elif field.type_ == "struct" and field.fields:
            chosen_field = random.choice(field.fields)
            self._mutate_field(chosen_field.content)

        elif field.type_ == "array" and field.content:
            self._mutate_field(field.content)

        else:
            pass

    def squash(self, prog):
        """syscall squash"""
        # squash operation
        pass


class Prog:
    def __init__(self):
        self.resources = {}  # 사용된 리소스 저장
        self.calls = []  # 추가된 syscall 리스트
        self.json_len = 0

    def __len__(self):
        if self.json_len == 0:
            self.json_len = 3000
        return self.json_len


    def to_json(self):
        """프로그램을 test case JSON 형식으로 변환"""
        test_case = []
        resource_ids = {resource: idx for idx, resource in enumerate(self.resources)}  # 리소스에 대한 id 부여

        for idx, call in enumerate(self.calls):
            call_json = {
                "name": call.call_name,
                "sysnum": call.sysnum,
                "argnum": call.argnum,
                "idx": idx
            }
            # 각 인자를 JSON 형식으로 변환
            for i, arg in enumerate(call.args, start=1):
                call_json[f"arg{i}"] = self.field_to_json(arg, resource_ids)
            test_case.append(call_json)
        result = json.dumps(test_case, indent=2)
        self.json_len = len(result)
        return result

    def field_to_json(self, field, resource_ids):
        """각 Field 객체를 JSON으로 변환 (재귀 처리)"""
        if field.type_ == "scalar":
            # 다양한 크기의 width를 처리 (1, 2, 4, 8)
            width_map = {
                1: "byte",
                2: "word",
                4: "dword",
                8: "qword"
            }
            return {
                "kind": width_map.get(field.width, "qword"),  # width에 따른 kind 결정
                "val": field.value if field.value is not None else 0
            }
        elif field.type_ == "ptr":
            # ptr 타입의 경우 재귀적으로 content를 처리
            if isinstance(field.content, Field):
                content_json = self.field_to_json(field.content, resource_ids)  # 재귀 처리
            else:
                content_json = 0

            # 리소스 사용 여부 확인
            if field.content and isinstance(field.content, Field) and field.content.type_ == "resource":
                field.width = field.content.width
                if field.direction == "in":
                     return {
                        "kind": "inptr",
                        "size": field.content.width,
                        "val": content_json
                    }
                elif field.direction == "out" or "inout":
                    content_json["kind"] = "inptr"
                    return content_json
                else:
                    return {
                        "kind": "qword",
                        "val": 0
                    }

            #string일 경우
            if field.content.type_ == "stringw":
                return {
                        "kind": "inptr",
                        "size": 256,
                        "val": {
                            "kind" : "string",
                            "val" : "test"
                        }
                }

            return {
                "kind": "inptr",
                "size": field.content.width,
                "val": content_json
            }

        elif field.type_ == "struct":
            # 구조체 내부 필드를 재귀적으로 처리하고, offset 정보를 포함
            struct_val = []
            field_size = 0
            for f in field.fields:
                content_json = self.field_to_json(f.content, resource_ids)
                content_json["offset"] = f.offset
                field_size += f.content.width
                struct_val.append(content_json)
            field.width = field_size
            return {
                "kind": "struct",
                "val": struct_val
            }

        elif field.type_ == "resource":
            resource_name = field.rsc_type  # 예: "h_file"

            if isinstance(resource_name, list):
                resource_names = [res for res in resource_name if res in self.resources]
                resource_name = random.choice(resource_names)

            if resource_name in resource_ids:
                field.width = self.resources[resource_name].width
                return {
                    "kind" : "retval",
                    "id" : resource_ids[resource_name],
                    "val" : 0,
                    "size" : self.resources[resource_name].width
                }
            else:
                return {
                    "kind" : "qword",
                    "val" : 0
                }

        elif field.type_ == "array":

            array_size = 0
            if field.is_size_dependent == True :
                array_size = field.size_reference_field.value

            else :
                if field.array_size_info.get("kind") == "fixed":
                    array_size = field.array_size_info.get("val")
                elif field.array_size_info.get("kind") == "unknown":
                    array_size = 1

            width = field.array_size_info.get("width")
            count = 0
            if field.countkind == "elem" :
                count = array_size
            if field.countkind == "byte" :

                count = array_size // width

            struct_val_list = list()
            for i in range(count):
                array_elem = self.field_to_json(field.content, resource_ids)
                array_elem["offset"] = i * field.content.width
                struct_val_list.append(array_elem)

            field.width = count * width
            return {
                "kind" : "struct",
                "val" : struct_val_list
            }
        elif field.type_ == "funcptr":
            field.width = 8
            return {
                "kind" : "funcptr",
                "val" : 0
            }

        return {"val": field.value if field.value is not None else 0}
