import os
import re
from dataclasses import dataclass
from typing import List, Dict, Optional
import pefile
import capstone
from concurrent.futures import ProcessPoolExecutor, as_completed
import sys

class Colors:
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

@dataclass
class SyscallDefinition:
    name: str
    return_type: str
    parameters: List[Dict[str, str]]
    offset: str
    description: Optional[str] = None

class TypeDefinitionTracker:
    def __init__(self):
        self.type_definitions = {}
        self.external_types = {
            'SYSTEM_INFORMATION_CLASS',
            'TRANSACTIONMANAGER_INFORMATION_CLASS',
            'RESOURCEMANAGER_INFORMATION_CLASS', 
            'ENLISTMENT_INFORMATION_CLASS',
            'PFILE_SEGMENT_ELEMENT',
            'EXECUTION_STATE',
            'JOBOBJECTINFOCLASS',
            'PSE_SIGNING_LEVEL',
            'SE_SIGNING_LEVEL',
            'PEXCEPTION_RECORD',
            'PJOB_SET_ARRAY',
            'PENCLAVE_ROUTINE',
            'NOTIFICATION_MASK',
            'volatile LONG *',
            'PIO_STATUS_BLOCK',
            'POBJECT_ATTRIBUTES',
            'PUNICODE_STRING',
            'SYSTEM_POWER_STATE',
            'POWER_ACTION',
            'PSECURITY_DESCRIPTOR',
            'TOKEN_INFORMATION_CLASS',
            'TRANSACTION_INFORMATION_CLASS',
            'THREADINFOCLASS',
            'PROCESSINFOCLASS',
            'KEY_SET_INFORMATION_CLASS',
            'OBJECT_INFORMATION_CLASS',
            'FILE_INFORMATION_CLASS',
            'LANGID',
            'PCONTEXT',
            'PSID',
            'PSECURITY_QUALITY_OF_SERVICE',
            'PKEY_VALUE_ENTRY',
            'PPRIVILEGE_SET',
            'POWER_INFORMATION_LEVEL',
            'CLIENT_ID *',
            'PMEM_EXTENDED_PARAMETER',
            'PTRANSACTION_NOTIFICATION',
            'PDEVICE_POWER_STATE',
            'PPROCESSOR_NUMBER',
            'OBJECT_ATTRIBUTES',
            'PTOKEN_GROUPS',
            'PTOKEN_PRIVILEGES',
            'KTMOBJECT_TYPE',
            'PKTMOBJECT_CURSOR',
            'TOKEN_TYPE',
            'PRTL_USER_PROCESS_PARAMETERS',
            'PTOKEN_USER',
            'PTOKEN_OWNER',
            'PTOKEN_PRIMARY_GROUP',
            'PTOKEN_DEFAULT_DACL',
            'PTOKEN_SOURCE',
            'PLUID',
            'PGROUP_AFFINITY',
            'PSID_AND_ATTRIBUTES',
            'PULARGE_INTEGER',
            'PGENERIC_MAPPING',
            'POBJECT_TYPE_LIST',
            'AUDIT_EVENT_TYPE',
            'PTOKEN_MANDATORY_POLICY'
        }
        self.parse_header_files()

    def parse_header_files(self):
        base_path = os.path.join(os.path.dirname(__file__), '..', '..')
        header_files = {
            'constants': os.path.join(base_path, "Wrapper", "include", "Sys", "sysConstants.h"),
            'types': os.path.join(base_path, "Wrapper", "include", "Sys", "sysTypes.h"),
            'externals': os.path.join(base_path, "Wrapper", "include", "Sys", "sysExternals.h")
        }
        for file_type, filepath in header_files.items():
            with open(filepath, 'r') as f:
                content = f.read()
            if file_type == 'constants':  # Parse #define constants
                defines = re.finditer(r'#define\s+(\w+)\s+(.+)', content)
                for match in defines:
                    name = match.group(1)
                    value = match.group(2)
                    self.type_definitions[name] = {
                        'file': 'sysConstants.h',
                        'definition': f'#define {name} {value}'
                    }
            comma_types = re.finditer(r'}\s*(\w+),\s*\*\s*(\w+);', content) # Parse types with comma separated pointer definitions
            for match in comma_types:
                base_type = match.group(1)
                ptr_type = match.group(2)
                self.type_definitions[base_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef struct {base_type}'
                }
                self.type_definitions[ptr_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef {base_type}* {ptr_type}'
                }
            ptr_types = re.finditer(r'typedef\s+(?:struct\s+)?(?:_)?(\w+)\s*\*\s*(\w+);', content) # Parse direct pointer typedefs
            for match in ptr_types:
                base_type = match.group(1)
                ptr_type = match.group(2)
                self.type_definitions[ptr_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef {base_type}* {ptr_type}'
                }
            basic_types = re.finditer(r'typedef\s+(?:struct\s+)?(?:_)?(\w+)\s+(\w+);', content) # Parse basic types (typedef)
            for match in basic_types:
                base_type = match.group(1)
                new_type = match.group(2)
                self.type_definitions[new_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef {base_type} {new_type}'
                }
            structs = re.finditer(r'typedef\s+struct\s+(?:_)?(\w+)\s*{[^}]+}\s*(\w+)\s*,\s*\*\s*(\w+);', content, re.DOTALL) # Parse struct definitions with pointer
            for match in structs:
                struct_name = match.group(2)
                ptr_name = match.group(3)
                self.type_definitions[struct_name] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': match.group(0)
                }
                self.type_definitions[ptr_name] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef {struct_name}* {ptr_name}'
                }
            enums = re.finditer(r'typedef\s+enum\s+(?:_)?(\w+)\s*{[^}]+}\s*(\w+);', content, re.DOTALL) # Parse enums
            for match in enums:
                enum_name = match.group(2)
                self.type_definitions[enum_name] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': match.group(0)
                }
            func_ptrs = re.finditer(r'typedef\s+\w+\s*\(\s*\w+\s*\*\s*(\w+)\s*\)\s*\([^)]*\)', content) # Parse function pointer types
            for match in func_ptrs:
                type_name = match.group(1)
                self.type_definitions[type_name] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef function_ptr {type_name}'
                }
            common_types = { # Add common Windows types
                'HANDLE', 'PVOID', 'BOOLEAN', 'ULONG', 'PULONG', 'ACCESS_MASK',
                'PHANDLE', 'PACCESS_MASK', 'PBOOLEAN', 'VOID',
                'ULONG_PTR', 'PULONG_PTR', 'ULONG64', 'PULONG64',
                'UCHAR', 'PUCHAR'
            }
            for type_name in common_types:
                self.type_definitions[type_name] = {
                    'file': 'sysTypes.h',
                    'definition': f'typedef base {type_name}'
                }
            const_ptr_types = re.finditer(r'typedef\s+const\s+(\w+)\s*\*\s*(\w+);', content) # Pattern for const pointer typedefs
            for match in const_ptr_types:
                base_type = match.group(1)
                new_type = match.group(2)
                self.type_definitions[new_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef const {base_type}* {new_type}'
                }
            wnf_types = re.finditer(r'typedef\s+(?:const\s+)?(?:struct\s+)?_?(\w+)\s*(?:\*\s*)?(\w+)(?:\s*,\s*\*\s*(\w+))?;', content) # Pattern for WNF specific types
            for match in wnf_types:
                base_type = match.group(1)
                new_type = match.group(2)
                ptr_type = match.group(3)
                self.type_definitions[new_type] = {
                    'file': f'sys{file_type.capitalize()}.h',
                    'definition': f'typedef {base_type} {new_type}'
                }
                if ptr_type:
                    self.type_definitions[ptr_type] = {
                        'file': f'sys{file_type.capitalize()}.h',
                        'definition': f'typedef {new_type}* {ptr_type}'
                    }
            # WNF_CHANGE_STAMP explicitly
            if 'WNF_CHANGE_STAMP' not in self.type_definitions:
                self.type_definitions['WNF_CHANGE_STAMP'] = {
                    'file': 'sysExternals.h',
                    'definition': 'typedef ULONG WNF_CHANGE_STAMP'
                }

    def check_type(self, type_name: str) -> Dict[str, str]:
        type_name = type_name.strip()
        if type_name in self.external_types:
            return {
                'file': 'Windows SDK',
                'definition': f'typedef external {type_name}'
            }
        if type_name.startswith('const '): # Handle const types
            type_name = type_name.replace('const ', '')
            type_name = type_name.strip()
        if ' *' in type_name: # Handle pointer with space (ULONG64 * -> ULONG64*)
            type_name = type_name.replace(' *', '*')
            base_type = type_name[:-1]
            ptr_type = 'P' + base_type
            if ptr_type in self.type_definitions:
                return self.type_definitions[ptr_type]
            if type_name in self.type_definitions: # Try direct lookup of pointer type
                return self.type_definitions[type_name]
        basic_types = { # Handle basic Windows types
            'LONG', 'ULONG', 'INT', 'UINT', 'CHAR', 'WCHAR', 'BOOL', 'BOOLEAN',
            'SHORT', 'USHORT', 'LONGLONG', 'ULONGLONG', 'BYTE', 'WORD', 'DWORD',
            'VOID', 'PVOID', 'HANDLE', 'SIZE_T', 'NTSTATUS',
            'ULONG_PTR', 'LONG', 'PLONG', 'PULONG_PTR', 'ULONG64', 'PULONG64',
            'UCHAR', 'PUCHAR', 'PCHAR', 'PUSHORT', 'PCSTR', 'PWSTR', 'PCWSTR', 'PCWCHAR'
        }
        if type_name in basic_types:
            return {
                'file': 'sysTypes.h',
                'definition': f'typedef base {type_name}'
            }
        if type_name.endswith('*'): # Handle pointer types
            base_type = type_name[:-1].strip()
            if base_type in self.type_definitions:
                return self.type_definitions[base_type]
            ptr_type = 'P' + base_type
            if ptr_type in self.type_definitions:
                return self.type_definitions[ptr_type]
        if type_name.startswith('P'): # Handle P prefixed types
            base_type = type_name[1:]
            if base_type in self.type_definitions:
                return self.type_definitions[base_type]
        return self.type_definitions.get(type_name, None) # Direct lookup

class SyscallVerification:
    def __init__(self):
        self.syscalls: Dict[str, SyscallDefinition] = {}
        self.test_results = []
        self.dll_path = os.getenv('NTDLL_PATH', "C:\\Windows\\System32\\ntdll.dll")
        self.type_tracker = TypeDefinitionTracker()

    def parse_syscall_definitions(self):
        base_path = os.path.join(os.path.dirname(__file__), '..', '..')
        try:
            from PyQt5.QtCore import QSettings
            settings = QSettings('SysCaller', 'BuildTools')
            syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
        except ImportError:
            syscall_mode = 'Nt'
        syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
        header_path = os.path.join(base_path, "Wrapper", "include", "Sys", "sysFunctions.h")
        asm_path = os.path.join(base_path, "Wrapper", "src", "syscaller.asm")
        with open(header_path, 'r') as f:
            content = f.read()
        pattern = rf'extern\s*"C"\s*(\w+)\s+((?:SC|{syscall_prefix})\w+)\s*\(([\s\S]*?)\)\s*;'
        matches = re.finditer(pattern, content, re.DOTALL)
        offsets = self.parse_syscall_offsets(asm_path) # Get syscall offsets from ASM file
        for match in matches:
            return_type = match.group(1)
            name = match.group(2)
            if name.startswith("SC"):
                name = syscall_prefix + name[2:]
            params_str = match.group(3).strip()
            params = [] # Parse parameters
            if params_str and params_str.upper() != 'VOID':
                param_list = params_str.split(',')
                for param in param_list:
                    param = param.strip()
                    param = re.sub(r'//.*$', '', param)  # Remove // comments
                    param = re.sub(r'/\*.*?\*/', '', param)  # Remove /* */ comments
                    param = param.strip()
                    if not param:
                        continue
                    if 'OPTIONAL' in param:
                        param_type = param.replace('OPTIONAL', '').strip()
                        is_optional = True
                    else:
                        param_type = param
                        is_optional = False
                    if param_type: 
                        param_parts = param_type.split()
                        if len(param_parts) > 0:
                            param_name = param_parts[-1]
                            param_type = ' '.join(param_parts[:-1])
                            param_type = param_type.split('//')[0].strip()
                            param_type = param_type.split('/*')[0].strip()
                            if param_type:
                                params.append({
                                    'type': param_type,
                                    'name': param_name,
                                    'optional': is_optional
                                })
            offset = offsets.get(name, "Unknown") # Get offset from ASM definitions
            self.syscalls[name] = SyscallDefinition(
                name=name,
                return_type=return_type,
                parameters=params,
                offset=offset
            )

    def parse_syscall_offsets(self, asm_path: str) -> Dict[str, str]:
        offsets = {}
        try:
            from PyQt5.QtCore import QSettings
            settings = QSettings('SysCaller', 'BuildTools')
            syscall_mode = settings.value('general/syscall_mode', 'Nt', str)
        except ImportError:
            syscall_mode = 'Nt'
        syscall_prefix = "Sys" if syscall_mode == "Nt" else "SysK"
        with open(asm_path, 'r') as f:
            content = f.read()
        pattern = r'((?:SC|Sys|SysK)\w+)\s+PROC[\s\S]*?mov\s+eax,\s+([\dA-Fa-fh]+)'
        matches = re.finditer(pattern, content)
        for match in matches:
            name = match.group(1)
            offset = match.group(2)
            if name.startswith("SC"):
                name = syscall_prefix + name[2:]
            offsets[name] = offset
        return offsets

    def test_syscall(self, syscall: SyscallDefinition) -> Dict:
        result = {
            'name': syscall.name,
            'status': 'SUCCESS',
            'offset': syscall.offset,
            'return_type': syscall.return_type,
            'parameter_count': len(syscall.parameters),
            'errors': [],
            'type_definitions': []
        }
        valid_return_types = {'NTSTATUS', 'BOOL', 'HANDLE', 'VOID', 'ULONG', 'ULONG_PTR', 'UINT32', 'UINT64'}
        if syscall.return_type not in valid_return_types:
            result['errors'].append(f"Unexpected return type: {syscall.return_type}")
        for param in syscall.parameters: 
            if not self.validate_parameter_type(param['type']):
                result['errors'].append(f"Invalid parameter type: {param['type']}")
        offset = syscall.offset.lower().replace('h', '') 
        try:
            offset_value = int(offset, 16)
            if offset_value > 0x0200:
                result['errors'].append(f"Suspicious syscall offset: 0x{offset} (expected range: 0x0000-0x0200)")
            expected_offset = self.get_offset_from_dll(syscall.name) # Get expected offset from ntdll
            if expected_offset and expected_offset != offset_value:
                result['errors'].append(
                    f"Offset mismatch: got 0x{offset}, expected 0x{expected_offset:X}"
                )
        except ValueError:
            result['errors'].append(f"Invalid syscall offset format: {syscall.offset}")
        for param in syscall.parameters:
            param_type = param['type']
            type_info = self.type_tracker.check_type(param_type) # Check parameter type definitions
            if not type_info:
                result['errors'].append(
                    f"Type '{param_type}' not found in header files"
                )
            else:
                result['type_definitions'].append({
                    'type': param_type,
                    'source_file': type_info['file']
                })
        if result['errors']:
            result['status'] = 'FAILED'
        return result

    def get_offset_from_dll(self, syscall_name: str) -> Optional[int]:
        try:
            pe = pefile.PE(self.dll_path)
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            if syscall_name.startswith("Sys"):
                base_name = syscall_name[3:]
            elif syscall_name.startswith("SysK"):
                base_name = syscall_name[4:]
            else:
                base_name = syscall_name
            primary_name = 'Nt' + base_name
            secondary_name = 'Zw' + base_name
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not export.name:
                    continue
                func_name = export.name.decode()
                if func_name in (primary_name, secondary_name):
                    func_rva = export.address
                    func_bytes = pe.get_data(func_rva, 16)
                    for instruction in md.disasm(func_bytes, func_rva):
                        if instruction.mnemonic == 'mov' and ('eax' in instruction.op_str or 'rax' in instruction.op_str):
                            parts = instruction.op_str.split(',')
                            if len(parts) == 2:
                                try:
                                    return int(parts[1].strip(), 16)
                                except ValueError:
                                    continue
            return None
        finally:
            if 'pe' in locals():
                pe.close()

    def validate_parameter_type(self, param_type: str) -> bool:
        valid_types = {
            'HANDLE', 'PHANDLE', 'PVOID', 'ULONG', 'PULONG', 'BOOLEAN',
            'POBJECT_ATTRIBUTES', 'ACCESS_MASK', 'PCLIENT_ID', 'PLARGE_INTEGER',
            'PPORT_MESSAGE', 'PPORT_VIEW', 'PREMOTE_PORT_VIEW',
            'PSECURITY_DESCRIPTOR', 'PGENERIC_MAPPING', 'PPRIVILEGE_SET',
            'PNTSTATUS', 'PSID',
            'PUNICODE_STRING',
            'POBJECT_TYPE_LIST',
            'AUDIT_EVENT_TYPE',
            'PLUID', 'PACCESS_MASK', 'PBOOLEAN', 'USHORT', 'UCHAR',
            'PCWSTR', 'PRTL_ATOM', 'PROCESS_ACTIVITY_TYPE',
            'PMEM_EXTENDED_PARAMETER', 'PSIZE_T', 'SIZE_T',
            'PALPC_PORT_ATTRIBUTES', 'PALPC_MESSAGE_ATTRIBUTES',
            'PALPC_CONTEXT_ATTR', 'PALPC_DATA_VIEW_ATTR',
            'PALPC_SECURITY_ATTR', 'PALPC_HANDLE',
            'PVOID*', 'PHANDLE*', 'PULONG*', 'PULONG_PTR',
            'PIO_STATUS_BLOCK', 'PFILE_INFORMATION_CLASS',
            'PSID_AND_ATTRIBUTES', 'PTOKEN_PRIVILEGES', 'PTOKEN_GROUPS',
            'PSECURITY_QUALITY_OF_SERVICE', 'SECURITY_INFORMATION',
            'SYSTEM_INFORMATION_CLASS', 'THREADINFOCLASS', 'PROCESSINFOCLASS',
            'JOBOBJECTINFOCLASS', 'DEBUGOBJECTINFOCLASS',
            'PBOOT_ENTRY', 'PEFI_DRIVER_ENTRY',
            'PTOKEN_SECURITY_ATTRIBUTES_INFORMATION',
            'PCOBJECT_ATTRIBUTES', 'MEMORY_RESERVE_TYPE',
            'PULARGE_INTEGER', 'PCHAR',
            'ALPC_PORT_INFORMATION_CLASS', 'ALPC_MESSAGE_INFORMATION_CLASS',
            'PROCESS_STATE_CHANGE_TYPE', 'THREAD_STATE_CHANGE_TYPE',
            'PENCLAVE_ROUTINE',
            'PT2_CANCEL_PARAMETERS', 'NTSTATUS',
            'LONG', 'PLONG', 'PWSTR', 'PCSTR', 'PCWCHAR',
            'LARGE_INTEGER', 'ULARGE_INTEGER',
            'KPRIORITY', 'PDEVICE_OBJECT', 'PEPROCESS',
            'PETHREAD', 'PSECTION_OBJECT', 'PLPC_MESSAGE',
            'PFILE_OBJECT', 'PKEVENT', 'PDRIVER_OBJECT',
            'PKTHREAD', 'PMDL', 'PPS_APC_ROUTINE',
            'PRTL_USER_PROCESS_PARAMETERS', 'PCONTEXT',
            'SE_SIGNING_LEVEL', 'LPCGUID', 'LPGUID',
            'EVENT_TYPE', 'NOTIFICATION_MASK',
            'KPROFILE_SOURCE', 'TIMER_TYPE',
            'PJOB_SET_ARRAY', 'POBJECT_BOUNDARY_DESCRIPTOR',
            'KAFFINITY', 'PGROUP_AFFINITY',
            'PINITIAL_TEB', 'PUSER_THREAD_START_ROUTINE',
            'PPS_ATTRIBUTE_LIST', 'PPS_CREATE_INFO',
            'TOKEN_TYPE', 'PTOKEN_USER', 'PTOKEN_OWNER',
            'PTOKEN_PRIMARY_GROUP', 'PTOKEN_DEFAULT_DACL',
            'PTOKEN_SOURCE', 'PTOKEN_MANDATORY_POLICY',
            'PWNF_STATE_NAME', 'PCWNF_STATE_NAME',
            'WNF_STATE_NAME_LIFETIME', 'WNF_DATA_SCOPE',
            'PCWNF_TYPE_ID',
            'PIO_APC_ROUTINE',
            'PCGUID', 'PGUID',
            'PTOKEN_GROUPS_AND_PRIVILEGES',
            'PSECURITY_DESCRIPTOR_RELATIVE',
            'PSID_AND_ATTRIBUTES_HASH',
            'PTOKEN_AUDIT_POLICY',
            'PTOKEN_PRIVILEGES_AND_GROUPS',
            'SECURITY_CONTEXT_TRACKING_MODE',
            'SECURITY_QUALITY_OF_SERVICE_FLAGS',
            'SECURITY_IMPERSONATION_LEVEL',
            'PTOKEN_ACCESS_INFORMATION',
            'PTOKEN_AUDIT_POLICY_INFORMATION',
            'KEY_INFORMATION_CLASS', 'KEY_VALUE_INFORMATION_CLASS',
            'KTMOBJECT_TYPE', 'PKTMOBJECT_CURSOR',
            'FILTER_BOOT_OPTION_OPERATION',
            'LANGID', 'PLCID',
            'PWNF_DELIVERY_DESCRIPTOR',
            'PPROCESSOR_NUMBER', 'DWORD',
            'PDEVICE_POWER_STATE', 'POWER_ACTION',
            'SYSTEM_POWER_STATE',
            'PTRANSACTION_NOTIFICATION',
            'PCM_EXTENDED_PARAMETER',
            'PARTITION_INFORMATION_CLASS',
            'DIRECTORY_NOTIFY_INFORMATION_CLASS',
            'IO_SESSION_EVENT', 'IO_SESSION_STATE',
            'OBJECT_ATTRIBUTES',
            'ULONG', 'ULONG_PTR', 'UINT32', 'UINT64',
            'PDEVICE_POWER_STATE_CONTEXT',
            'PPOWER_SESSION_ALLOW_EXTERNAL_DMA_DEVICES',
            'PPOWER_SESSION_RIT_STATE',
            'PSYSTEM_POWER_POLICY',
            'PDEVICE_NOTIFY_SUBSCRIBE_PARAMETERS',
            'PFILE_NOTIFY_INFORMATION',
            'PKEY_VALUE_ENTRY',
            'PKEY_NAME_INFORMATION',
            'PKEY_CACHED_INFORMATION',
            'PKEY_VIRTUALIZATION_INFORMATION',
            'PKEY_WRITE_TIME_INFORMATION',
            'PLUGPLAY_CONTROL_CLASS',
            'POWER_INFORMATION_LEVEL',
            'PNTPSS_MEMORY_BULK_INFORMATION',
            'MEMORY_INFORMATION_CLASS',
            'PFILE_BASIC_INFORMATION',
            'PBOOT_OPTIONS',
            'FILE_INFORMATION_CLASS',
            'FSINFOCLASS',
            'PFILE_SEGMENT_ELEMENT',
            'EVENT_INFORMATION_CLASS',
            'ATOM_INFORMATION_CLASS',
            'ENLISTMENT_INFORMATION_CLASS',
            'PORT_INFORMATION_CLASS',
            'RESOURCEMANAGER_INFORMATION_CLASS',
            'TOKEN_INFORMATION_CLASS',
            'TRANSACTION_INFORMATION_CLASS',
            'TRANSACTIONMANAGER_INFORMATION_CLASS',
            'WORKERFACTORYINFOCLASS',
            'IO_COMPLETION_INFORMATION_CLASS',
            'MUTANT_INFORMATION_CLASS',
            'OBJECT_INFORMATION_CLASS',
            'SECTION_INFORMATION_CLASS',
            'SEMAPHORE_INFORMATION_CLASS',
            'TIMER_INFORMATION_CLASS',
            'PCUNICODE_STRING',
            'SECURE_SETTING_VALUE_TYPE',
            'PWNF_CHANGE_STAMP',
            'WNF_STATE_NAME_INFORMATION',
            'PEXCEPTION_RECORD',
            'PCRM_PROTOCOL_ID',
            'PFILE_IO_COMPLETION_INFORMATION',
            'PFILE_INFORMATION',
            'PSECURITY_POLICY_INFORMATION',
            'PPROCESS_INFORMATION',
            'PTOKEN_INFORMATION',
            'PMUTANT_INFORMATION',
            'PSEMAPHORE_INFORMATION',
            'PTIMER_INFORMATION',
            'PPORT_INFORMATION',
            'PRESOURCEMANAGER_INFORMATION',
            'PTRANSACTION_INFORMATION',
            'PTRANSACTIONMANAGER_INFORMATION',
            'PWORKER_FACTORY_INFORMATION',
            'PIO_COMPLETION_INFORMATION',
            'PSECTION_INFORMATION',
            'POBJECT_INFORMATION',
            'PVOLUME_INFORMATION',
            'PWNF_STATE_INFORMATION',
            'PEXCEPTION_INFORMATION',
            'PPROTOCOL_INFORMATION',
            'SE_SET_FILE_CACHE_INFORMATION',
            'SE_SET_FILE_CACHE_INFORMATION *',
            'LCID',
            'KEY_SET_INFORMATION_CLASS',
            'SYMBOLIC_LINK_INFO_CLASS',
            'PMEMORY_RANGE_ENTRY',
            'EXECUTION_STATE',
            'EXECUTION_STATE *',
            'PTIMER_APC_ROUTINE',
            'PT2_SET_PARAMETERS',
            'TIMER_SET_INFORMATION_CLASS',
            'SHUTDOWN_ACTION',
            'SYSDBG_COMMAND',
            'ETWTRACECONTROLCODE',
            'PFILE_PATH',
            'WNF_CHANGE_STAMP',
            'LOGICAL',
            'VDMSERVICECLASS',
            'PDBGUI_WAIT_STATE_CHANGE',
            'WAIT_TYPE',
            'PWORKER_FACTORY_DEFERRED_WORK',
            'PSE_SET_FILE_CACHE_INFORMATION',
            'PEXECUTION_STATE',
            'PTIMER_SET_INFORMATION',
            'PSHUTDOWN_ACTION',
            'PSYSDBG_COMMAND',
            'PETWTRACECONTROLCODE',
            'PVDMSERVICECLASS',
            'PWORKER_FACTORY_INFORMATION',
            'PDBGUI_WAIT_STATE_CHANGE',
            'PWAIT_TYPE',
            'PLOGICAL',
            'PFILE_PATH_INFORMATION',
            'PFILE_NETWORK_OPEN_INFORMATION'
        }
        param_type = param_type.strip()
        if not param_type: 
            return False
        if param_type.startswith('const '): # Handle const types
            param_type = param_type[6:]
        if param_type.endswith('*'): # Handle pointer types
            base_type = param_type[:-1].strip()
            pointer_type = 'P' + base_type
            return (base_type in valid_types or pointer_type in valid_types or
                    any(valid_type in base_type for valid_type in valid_types))
        if '[' in param_type: # Handle array types
            param_type = param_type[:param_type.index('[')].strip()
        if param_type.startswith('LP'): # Handle LP prefix (Long Pointer)
            alt_type = 'P' + param_type[2:]
            return (param_type in valid_types or alt_type in valid_types or
                    any(valid_type in param_type for valid_type in valid_types))
        return (param_type in valid_types or
                any(valid_type in param_type for valid_type in valid_types)) 

    def run_tests(self, output_format='console'):
        self.parse_syscall_definitions()
        print(f"{Colors.BOLD}Testing {len(self.syscalls)} syscalls...{Colors.ENDC}\n")
        batch_size = 100
        syscall_list = list(self.syscalls.values())
        for i in range(0, len(syscall_list), batch_size):
            batch = syscall_list[i:i + batch_size]
            with ProcessPoolExecutor() as executor:
                future_to_syscall = {
                    executor.submit(self.test_syscall, syscall): syscall.name 
                    for syscall in batch
                }
                for future in as_completed(future_to_syscall):
                    syscall_name = future_to_syscall[future]
                    try:
                        result = future.result()
                        self.test_results.append(result)
                        if output_format == 'console':
                            self.print_result(result)
                    except Exception as e:
                        print(f"{Colors.FAIL}Error testing {syscall_name}: {str(e)}{Colors.ENDC}")
          
    def print_result(self, result: Dict):
        use_ascii = '--from-gui' in sys.argv
        tree_chars = {
            'branch': '|--' if use_ascii else '├─',
            'last': '`--' if use_ascii else '└─',
            'indent': '   ' if use_ascii else '   '
        }
        output = []
        output.append(f"{Colors.BOLD}{result['name']}{Colors.ENDC}")
        output.append(f"{tree_chars['branch']} Status: {Colors.OKGREEN if result['status'] == 'SUCCESS' else Colors.FAIL}{result['status']}{Colors.ENDC}")
        output.append(f"{tree_chars['branch']} Offset: {Colors.OKBLUE}0x{result['offset'].replace('h','')}{Colors.ENDC}")
        output.append(f"{tree_chars['branch']} Return Type: {result['return_type']}")
        output.append(f"{tree_chars['last']} Parameters: {result['parameter_count']}")
        if result['type_definitions']:
            output.append(f"{tree_chars['indent']}|-- Type Definitions:")
            for i, type_def in enumerate(result['type_definitions']):
                is_last = i == len(result['type_definitions']) - 1 and not result['errors']
                prefix = tree_chars['last'] if is_last else tree_chars['branch']
                output.append(f"{tree_chars['indent']}   {prefix} {type_def['type']}: {Colors.OKBLUE}{type_def['source_file']}{Colors.ENDC}")
        if result['errors']:
            output.append(f"{tree_chars['indent']}|-- Errors:")
            for i, error in enumerate(result['errors']):
                prefix = tree_chars['last'] if i == len(result['errors']) - 1 else tree_chars['branch']
                output.append(f"{tree_chars['indent']}   {prefix} {Colors.FAIL}{error}{Colors.ENDC}")
        print('\n'.join(output), flush=True)
        print()

if __name__ == "__main__":
    def run_verification():
        tester = SyscallVerification()
        sys.stdout.flush()
        tester.run_tests()
        sys.stdout.flush()
        print()
    run_verification() 
