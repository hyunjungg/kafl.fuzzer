import json

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

    def parse_field(self, name: str, field_json: dict) -> 'Field':
        """필드 데이터를 파싱하여 Field 객체로 변환"""
        type_ = field_json.get("type")
        direction = field_json.get("inout")
        has_direction = direction in {"out", "inout"}
        content = None
        fieldcount = field_json.get("fieldcount")
        width = field_json.get("width")
        offset = field_json.get("offset")
        fields = []

        field = Field(name, type_, has_direction, direction, content, fieldcount, width, offset, fields)

        # 리소스가 의존하는 데이터 처리
        # if isinstance(field_json.get("content"), str):
        #     resource_name = field_json["content"]
        #     field.content = self.resources_desc.get(resource_name)

        # content가 dict인 경우, 재귀적으로 파싱
        if isinstance(field_json.get("content"), dict):
            field.content = self.parse_field(name, field_json["content"])

        if type_ == "struct": # struct 타입인 경우 필드들의 리스트 파싱
            for field_index_json in field_json["fields"]:
                struct_field = self.parse_field(name, field_index_json)
                struct_field.offset = field_index_json["offset"]
                field.fields.append(struct_field)

        elif type_ == "resource": # resource 타입인 경우
            field.is_resource = True
            field.content = field_json["content"]


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
                        field = self.parse_field(arg_name, syscall_value[arg_name])
                        syscall.add_field(field)

                # 파싱된 syscall 객체를 리스트에 추가
                syscalls.append(syscall)

            return syscalls

    def deserialize_resources(self, type_json: dict):

        """리소스를 파싱하여 Field 객체로 변환 및 저장"""
        for resource_name, resource_desc in type_json["resources"].items():
            self.resources_desc[resource_name] = self.parse_field(None, resource_desc)

        self.resources_usage_desc = {key: {"create": [], "use": []} for key in self.resources_desc}

    def process_resource_usage(self):
        for syscall in self.syscalls:
            for field in syscall.args:
                # 부모 필드의 inout 정보 추출
                direction = field.direction
                if field.type_ == "ptr" and isinstance(field.content, Field):
                    content_field = field.content
                    if content_field.type_ == "resource":
                        resource_name = content_field.content
                        if resource_name:
                            if isinstance(resource_name, list):
                                for res in resource_name:
                                    if res in self.resources_usage_desc:
                                        if direction == "out":
                                            self.resources_usage_desc[res]["create"].append(syscall)
                                        elif direction == "inout" or direction == "in":
                                            self.resources_usage_desc[res]["use"].append(syscall)
                            else:
                                if resource_name in self.resources_usage_desc:
                                    if direction == "out":
                                        self.resources_usage_desc[resource_name]["create"].append(syscall)
                                    elif direction == "inout" or direction == "in":
                                        self.resources_usage_desc[resource_name]["use"].append(syscall)


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

class Field:
    def __init__(self, name: str, type_: str, has_direction: bool, direction: str, content, fieldcount, width, offset, fields):
        self.name = name
        self.type_ = type_
        self.has_direction = has_direction
        self.direction = direction
        self.content = content
        self.value = None
        self.fieldcount = fieldcount
        self.width = width
        self.offset = offset
        self.fields = fields if fields else []
        self.is_resource = False # not used yet

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
