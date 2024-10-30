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
            # 리소스를 생성하거나 사용하는 syscall 랜덤 선택
            # if random.randint(0, 1) == 0:
            #     resources = self.syscall_manager.get_resources_desc()
            #     random_resource = random.choice(list(resources.keys()))
            #     resource_creating_syscalls = self.syscall_manager.get_resource_creating_syscalls(random_resource)
            #     new_call = random.choice(resource_creating_syscalls)  # 무작위로 syscall 선택
            # else:
            #     new_call = self.syscall_manager.get_resource_using_syscall(prog.resources)
            resource = random.choice(list(prog.resources.keys()))
            resource_using_syscalls = self.syscall_manager.get_resource_use_syscalls(resource)
            new_call = random.choice(resource_using_syscalls)


        prog.calls.append(new_call)

        # To Do : new_call value 세팅 추가



    def mutate_arg(self, prog):
        """argument를 mutation"""
        if not prog.calls:
            return  # syscalls가 비어있는 경우 함수 종료

        # Step 1: prog.syscalls 리스트에서 무작위로 하나의 syscall 선택
        chosen_syscall = random.choice(prog.calls)
        print(chosen_syscall.call_name)

        if not chosen_syscall.args:
            return  # args가 비어있는 경우 함수 종료

        # Step 2: args 중 무작위로 하나 선택 후 mutation
        chosen_arg = random.choice(chosen_syscall.args)
        print(chosen_arg.name)
        self._mutate_field(chosen_arg)

    def _mutate_field(self, field):
        """Field를 mutation (재귀적으로 필드 내부에서 선택)"""
        if field.type_ == "scalar" and field.width:
            # scalar 타입일 경우 width에 따라 값 변형
            field.value = random.randint(0, (2 ** (field.width * 8)) - 1)

        elif field.type_ == "ptr" and field.content:
            # ptr 타입일 경우 content 필드를 재귀적으로 처리
            self._mutate_field(field.content)

        elif field.type_ == "struct" and field.fields:
            # struct 타입일 경우 필드 중 하나를 무작위로 선택해 재귀적으로 처리
            struct_field = random.choice(field.fields)
            self._mutate_field(struct_field.content)

        elif field.type_ == "array" and field.content:
            pass

    def squash(self, prog):
        """syscall squash"""
        # squash operation
        pass


class Prog:
    def __init__(self):
        self.resources = {}  # 사용된 리소스 저장
        self.calls = []  # 추가된 syscall 리스트


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
        return json.dumps(test_case, indent=2)

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

            # 리소스 사용 여부를 content.type에서 확인하고, resource_id를 부여
            if field.content and isinstance(field.content, Field) and field.content.type_ == "resource":
                resource_name = field.content.content  # 예: "h_file"
                if resource_name in resource_ids:
                    if field.direction == "in" or "inout":
                        return {
                            "kind": "retval",
                            "id": resource_ids[resource_name],
                        }
                    elif field.direction == "out":
                        return {
                            "kind": "inptr",
                            "id": resource_ids[resource_name],
                            "size": field.width if field.width else 0,
                            "val": 0
                        }
                else : # resource가 생성되지 않은 경우에는 resource_ids 목록에 resource name이 있지 않음
                    return {
                        "kind":"qword",
                        "val" : 0
                    }
                        #string일 경우
            # string 임시 처리
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
                "size": field.width if field.width else 0,
                "val": content_json
            }
        elif field.type_ == "struct":
            # 구조체 내부 필드를 재귀적으로 처리하고, offset 정보를 포함
            struct_val = []
            for f in field.fields:
                content_json = self.field_to_json(f.content, resource_ids)
                content_json["offset"] = f.offset
                struct_val.append(content_json)
            return {
                "kind": "struct",
                "val": struct_val
            }

        elif field.type_ == "array":
            # 배열 타입도 각 요소를 재귀적으로 처리
            # return {
            #     "kind": "struct",
            #     "val": [self.field_to_json(f, resource_ids) for f in field.content]
            # }

            return {
                "kind" : "scalar",
                "val" : 0
            }
        return {"val": field.value if field.value is not None else 0}
