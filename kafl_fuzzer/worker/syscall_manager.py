import json
import random

class SyscallManager:
    def __init__(self):
        self.resources_desc = {}  # 리소스 정보를 저장하는 딕셔너리
        self.resources_usage_desc = {}  # 리소스 사용 정보를 저장하는 딕셔너리
        self.syscalls = []  # 시스템 호출을 저장하는 리스트

    def get_resources_desc(self):
        return self.resources_desc

    def get_resource_create_syscalls(self, resource_name):
        return self.resources_usage_desc[resource_name]["create"]

    def get_resource_use_syscalls(self, resource_name):
        return self.resources_usage_desc[resource_name]["use"]

    def parse_field(self, syscall, arg_name: str, field_json: dict) -> 'Field':
        """필드 데이터를 파싱하여 Field 객체로 변환"""
        type_ = field_json.get("type")
        direction = field_json.get("inout")
        has_direction = direction in {"out", "inout"}
        content = None
        rsc_type = field_json.get("rsc_type")
        fieldcount = field_json.get("fieldcount")
        width = field_json.get("width", 0)
        offset = field_json.get("offset")
        fields = []
        countkind = field_json.get("countkind")

        field = Field(syscall, arg_name, type_, has_direction, direction, content, rsc_type, fieldcount, width, offset, fields, countkind)

        # content가 dict인 경우, 재귀적으로 파싱
        if isinstance(field_json.get("content"), dict):
            field.content = self.parse_field(syscall, arg_name, field_json["content"])


        if type_ == "array" :
            size_info = field_json.get("size")
            size_info["width"] = field_json.get("width")

            if size_info["kind"] == "argfield":
                field.is_size_dependent = True
                field.array_size_info = size_info

            elif size_info["kind"] == "adjacentfield":
                field.is_size_dependent = True
                offset = size_info["offsets"]
                field.array_size_info = size_info

            elif size_info["kind"] == "fixed":
                field.array_size_info = size_info

            elif size_info["kind"] == "unknown":
                field.array_size_info = size_info

            else:
                print(f"[!] not supported array type {size_info['kind']}\n")


        if type_ == "struct": # struct 타입인 경우 필드들의 리스트 파싱
            for field_index_json in field_json["fields"]:
                struct_field = self.parse_field(syscall, arg_name, field_index_json)
                struct_field.content.struct_parent = field
                field.fields.append(struct_field)

        elif type_ == "resource": # resource 타입인 경우
            field.is_resource = True
            field.rsc_type = field_json["rsc_type"]
            field.rsc_direction = "in"

        elif type_ == "ptr":
            field.width = 8
            if field_json.get("content").get("type") == "resource":
                field.content.rsc_direction = direction

        elif type_ == "scalar":
            field.value = random.randint(1, (2 ** (field.width)) - 1)


        return field

    def parse_syscalls(self, type_json: dict) -> list:
            """시스템 호출 정보를 파싱하여 Syscall 객체로 변환"""
            syscalls = []

            for syscall_name, syscall_value in type_json.items():
                sysnum = syscall_value["sysnum"]
                argnum = syscall_value["argnum"]
                call_name = syscall_name
                syscall = Syscall(sysnum, argnum, call_name)

                # Field 정보 파싱 및 추가
                for i in range(1, argnum + 1):
                    arg_name = f"arg{i}"
                    if arg_name in syscall_value:
                        field = self.parse_field(syscall, arg_name, syscall_value[arg_name])
                        syscall.add_field(field)

                # 파싱된 syscall 객체를 리스트에 추가
                syscalls.append(syscall)

            return syscalls

    def deserialize_resources(self, type_json: dict):

        """리소스를 파싱하여 Field 객체로 변환 및 저장"""
        for resource_name, resource_desc in type_json["resources"].items():
            self.resources_desc[resource_name] = self.parse_field(None, None, resource_desc)

        self.resources_usage_desc = {key: {"create": [], "use": []} for key in self.resources_desc}

    def process_resource_usage(self):
        for syscall in self.syscalls:
            for field in syscall.args:
                self.iterate_field_for_resource(field, syscall)

    def find_field_by_arg_name(self, syscall, idx):
        return syscall.args[idx]

    def find_field_by_parent_struct(self, struct_parent, offset):
        offset = offset[0]
        for field in struct_parent.fields:
            if field.offset == offset:
                return field.content
        return None

    def iterate_field_for_array(self , field, syscall):

        if field.is_size_dependent == True :
            kind = field.array_size_info.get("kind")
            idx = field.array_size_info.get("idx")
            offset = field.array_size_info.get("offsets")

            if kind == "argfield":
                field.size_reference_field = self.find_field_by_arg_name(field.syscall, idx)

            if kind == "adjacentfield":
                field.size_reference_field = self.find_field_by_parent_struct(field.struct_parent, offset)

        if field.type_ == "ptr":
            if isinstance(field.content, Field):
                self.iterate_field_for_array(field.content , syscall)

        elif field.type_ == "struct":
            for f in field.fields:
                self.iterate_field_for_array(f.content, syscall)

        elif field.type_ == "array":
            if isinstance(field.content, Field):
                self.iterate_field_for_array(field.content , syscall)

        elif field.type_ == "resource":
            pass

    def set_array_size_reference_field(self):
        for syscall in self.syscalls:
            for field in syscall.args:
                self.iterate_field_for_array(field, syscall)


    def iterate_field_for_resource(self , field, syscall):
        if field.type_ == "ptr":
            if isinstance(field.content, Field):
                self.iterate_field_for_resource(field.content , syscall)

        elif field.type_ == "struct":
            for f in field.fields:
                self.iterate_field_for_resource(f.content, syscall)

        elif field.type_ == "array":
            if isinstance(field.content, Field):
                self.iterate_field_for_resource(field.content , syscall)

        elif field.type_ == "resource":
            if isinstance(field.rsc_type, list):
                for res in field.rsc_type:
                    if res in self.resources_usage_desc:
                        if field.rsc_direction == "in":
                            self.resources_usage_desc[res]["use"].append(syscall)
                        else:
                            self.resources_usage_desc[res]["create"].append(syscall)
            else:
                if field.rsc_type in self.resources_usage_desc:
                    if field.rsc_direction == "in":
                        self.resources_usage_desc[field.rsc_type]["use"].append(syscall)
                    else:
                        self.resources_usage_desc[field.rsc_type]["create"].append(syscall)


    def load_type_json(self, path: str):
        """JSON 파일을 읽어 리소스 및 시스템 호출 파싱"""
        with open(path, 'r') as f:
            type_json = json.load(f)

            # 리소스 파싱
            self.deserialize_resources(type_json)

            # 리소스 항목을 제외한 syscall 파싱
            del type_json['resources']
            self.syscalls = self.parse_syscalls(type_json)

            # 리소스 사용 정보 update
            self.process_resource_usage()

            # array의 size 정보 update
            self.set_array_size_reference_field()

class Field:
    def __init__(self, syscall, name: str, type_: str, has_direction: bool, direction: str, content, rsc_type, fieldcount, width, offset, fields, countkind):
        self.syscall = syscall
        self.name = name
        self.type_ = type_
        self.has_direction = has_direction
        self.direction = direction
        self.content = content
        self.rsc_type = rsc_type
        self.value = None
        self.fieldcount = fieldcount
        self.width = width
        self.offset = offset
        self.fields = fields if fields else []
        self.is_resource = False
        self.rsc_direction = None
        self.countkind = countkind
        self.struct_parent = None # 필드가 속한 구조체 객체를 저장
        self.is_size_dependent = False # array 일때, 크기가 동적으로 결정되는 경우 True
        self.size_reference_field = None # array 일때, 크기를 결정하는 필드의 객체를 저장

class Syscall:
    def __init__(self, sysnum: int, argnum: int, call_name: str, args: list = None, creates_resources: list = None, uses_resources: list = None):
        self.sysnum = sysnum
        self.argnum = argnum
        self.call_name = call_name
        self.args = args if args else []  # args를 빈 리스트로 초기화
        self.creates_resources = creates_resources if creates_resources else []
        self.uses_resources = uses_resources if uses_resources else []
        # To do : syscall이 argument에 dependency 한지 아닌지 확인하는 flag 추가

    def add_field(self, field: Field):
        self.args.append(field)
