import pefile
import ctypes
import os

class CPUIDRegisters(ctypes.Structure):
    _fields_ = [(r, ctypes.c_uint32) for r in ("eax", "ebx", "ecx", "edx")]

class CPUID(object):
    # Assembly-level instructions for CPUID on 32/64-bit architectures
    _OPC_32 = [
        0x53,                    # push   %ebx
        0x57,                    # push   %edi
        0x8b, 0x7c, 0x24, 0x0c,  # mov    0xc(%esp),%edi
        0x8b, 0x44, 0x24, 0x10,  # mov    0x10(%esp),%eax
        0x0f, 0xa2,              # cpuid
        0x89, 0x07,              # mov    %eax,(%edi)
        0x89, 0x5f, 0x04,        # mov    %ebx,0x4(%edi)
        0x89, 0x4f, 0x08,        # mov    %ecx,0x8(%edi)
        0x89, 0x57, 0x0c,        # mov    %edx,0xc(%edi)
        0x5f,                    # pop    %edi
        0x5b,                    # pop    %ebx
        0xc3                     # ret
    ]
    _OPC_64 = [
        0x53,                    # push   %rbx
        0x48, 0x89, 0xd0,        # mov    %rdx,%rax
        0x49, 0x89, 0xc8,        # mov    %rcx, %r8
        0x0f, 0xa2,              # cpuid
        0x41, 0x89, 0x00,        # mov    %eax,(%r8)
        0x41, 0x89, 0x58, 0x04,  # mov    %ebx,0x4(%r8)
        0x41, 0x89, 0x48, 0x08,  # mov    %ecx,0x8(%r8)
        0x41, 0x89, 0x50, 0x0c,  # mov    %edx,0xc(%r8)
        0x5b,                    # pop    %rbx
        0xc3                     # retq
    ]

    # Parameters for VirtualAlloc and VirtualFree
    _PAGE_EXECUTE_READWRITE = 0x40
    _MEM_COMMIT  = 0x1000
    _MEM_RESERVE = 0x2000
    _MEM_RELEASE = 0x8000

    def __init__(self, restype, argtypes, is_64_bit):                            
        # Load in kernel32.dll
        self.kernel32_dll = ctypes.WinDLL("C:\\Windows\\System32\\kernel32.dll")
        opc = self._OPC_64 if is_64_bit == True else self._OPC_32
        self.instructions = "".join((chr(x) for x in opc))
        self.buffer = self.kernel32_dll.VirtualAlloc(None, len(self.instructions),
            (self._MEM_COMMIT | self._MEM_RESERVE), self._PAGE_EXECUTE_READWRITE)
        ctypes.memmove(self.buffer, self.instructions, len(self.instructions))
        proto_func = ctypes.CFUNCTYPE(restype, *argtypes)
        self.cpuid = proto_func(self.buffer)

    def __call__(self, *args):
        return self.cpuid(*args)

    def __del__(self):
        if self.buffer is not None:
            self.kernel32_dll.VirtualFree(self.buffer, 0, self._MEM_RELEASE)
            self.buffer = None

class AntiExploitation(object):
    # List of applications to check
    APPS_TO_CHECK = {
        '7-Zip': ['7z.exe','7zG.exe','7zFM.exe'],
        'Adobe': ['AcroRd32.exe','Acrobat.exe','Photoshop.exe'],
        'Foxit Reader': ['Foxit Reader.exe'],
        'Google': ['chrome.exe','googletalk.exe'],
        'Internet Explorer': ['iexplore.exe'],
        'iTunes': ['iTunes.exe'],
        'Java': ['java.exe','javaw.exe','javaws.exe'],
        'Microsoft Lync': ['communicator.exe'],
        'Microsoft Office': ['OUTLOOK.EXE','LYNC.EXE','WINWORD.EXE',
            'EXCEL.EXE','POWERPNT.EXE','MSPUB.EXE','INFOPATH.EXE',
            'VISIO.EXE','PPTVIEW.EXE','OIS.EXE','MSACCESS.EXE'],
        'mIRC': ['mirc.exe'],
        'Mozilla Firefox': ['firefox.exe','plugin-container.exe'],
        'Mozilla Thunderbird': ['thunderbird.exe','plugin-container.exe'],
        'Opera': ['opera.exe'],
        'Pidgin': ['pidgin.exe'],
        'QuickTime': ['QuickTimePlayer.exe'],
        'Real': ['realconverter.exe','realplay.exe'],
        'Safari': ['Safari.exe'],
        'SkyDrive': ['SkyDrive.exe'],
        'Skype': ['Skype.exe'],
        'VideoLAN': ['vlc.exe'],
        'Winamp': ['winamp.exe'],
        'Windows Live': ['WindowsLiveWriter.exe','wlmail.exe',
            'WLXPhotoGallery.exe'],
        'Windows Media Player': ['wmplayer.exe'],
        'WinRAR': ['winrar.exe','rar.exe','unrar.exe'],
        'WinZip': ['winzip32.exe','winzip64.exe']
    }

    # IMAGE OPTIONAL HEADER parameters indicating application supports
    # ASLR (DYNAMIC_BASE) and DEP (NX_COMPAT).
    _IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    _IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100

    # Windows system error codes, used for checking the firmware type
    _ERROR_INVALID_FUNCTION = 1
    _ERROR_NOACCESS = 998

    # Bit positions for CPUID registers
    _BIT6 = 0x40
    _BIT7 = 0x80
    _BIT20 = 0x100000

    def __init__(self):
        # Determine if Python is running in 64-bit mode
        self._is_64_bit = bool(ctypes.sizeof(ctypes.c_int) == 8)

        # Set up function prototype for CPUID call
        self._cpuid = CPUID(None, [ctypes.POINTER(CPUIDRegisters), ctypes.c_uint32],
            self._is_64_bit)

        # Check for existence of each app in APPS_TO_CHECK
        # Populate installed_apps with apps that exist on the system
        self.installed_apps = []
        for key in self.APPS_TO_CHECK:
            # 64-bit apps
            full_path_64 = 'C:\Program Files\\' + key
            if os.path.isdir(full_path_64):
                for app in self.APPS_TO_CHECK[key]:
                    for root,dirs,files in os.walk(full_path_64):
                        if app in files:
                            self.installed_apps.append(os.path.join(root,app))
            # 32-bit apps
            full_path_32 = 'C:\Program Files (x86)\\' + key
            if os.path.isdir(full_path_32):
                for app in self.APPS_TO_CHECK[key]:
                    for root,dirs,files in os.walk(full_path_32):
                        if app in files:
                            self.installed_apps.append(os.path.join(root,app))

    # Compare application IMAGE_OPTIONAL_HEADER DLL characteristics
    # against DYNAMIC_BASE to check for ASLR support
    def checkApplicationForAslr(self,app):
        return bool(app.OPTIONAL_HEADER.DllCharacteristics & 
	        self._IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0)

    # Compare application IMAGE_OPTIONAL_HEADER DLL characteristics
    # against NX_COMPAT to check for DEP support
    def checkApplicationForDep(self,app):
        return bool(app.OPTIONAL_HEADER.DllCharacteristics & 
            self._IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0)

    # Create a NULL pointer and attempt to write to it
    def checkNullPageMapping(self):
        try:
            null_ptr = ctypes.POINTER(ctypes.c_int)()
            null_ptr[0] = 7
            return True
        except ValueError:
            return False

    # Check the firmware environment variable from kernel32.dll to check for
    # legacy BIOS or UEFI modes
    def checkFirmwareType(self):
        # Load in kernel32.dll
        kernel32_dll = ctypes.WinDLL("C:\\Windows\\System32\\kernel32.dll")

        # Because we're using bogus parameters in the function call, it
        # should always fail (return 0).
        if kernel32_dll.GetFirmwareEnvironmentVariableW(ctypes.c_wchar_p(""),
            ctypes.c_wchar_p("{00000000-0000-0000-0000-000000000000}"), None,
            ctypes.c_int(0)) == 0:
            # Check the last error returned to determine firmware type.
            # If the error is anything other than ERROR_INVALID_FUNCTION
            # or ERROR_NOACCESS, raise an exception.
            last_error = ctypes.GetLastError()
            if last_error == self._ERROR_INVALID_FUNCTION:
                return "Legacy"
            elif last_error == self._ERROR_NOACCESS:
                return "UEFI"
            else:
                raise ctypes.WinError()
        else:
            return "Unknown"

    # Check for PAE, SMEP, SMAP, and NX hardware support using CPUID.
    def checkHardwareSupport(self):
        hardware_support = {k:'UNKNOWN' for k in ("PAE","NX","SMAP","SMEP")}
        registers = CPUIDRegisters()

        # Determine highest leaf
        self._cpuid(registers, 0)
        highest_leaf = registers.eax
        self._cpuid(registers, 0x80000000)
        highest_extended_leaf = registers.eax

        # Check for PAE support
        if highest_leaf >= 1:
            self._cpuid(registers,1)
            hardware_support['PAE'] = bool(registers.edx & self._BIT6 != 0)

        # Check for SMEP/SMAP support
        if highest_leaf >=7:
            self._cpuid(registers,7)
            hardware_support['SMEP'] = bool(registers.edx & self._BIT7)
            hardware_support['SMAP'] = bool(registers.edx & self._BIT20)

        # Check for NX support
        if highest_extended_leaf >= 0x80000001:
            self._cpuid(registers,0x80000001)
            hardware_support['NX'] = bool(registers.edx & self._BIT20)

        return hardware_support

if __name__ == "__main__":

    ae = AntiExploitation()

    # For each installed app, check ASLR and DEP support
    for app in ae.installed_apps:
        if os.path.isfile(app):
            try:
                pe = pefile.PE(app,True)

                # ASLR check
                if ae.checkApplicationForAslr(pe):
                  print "%s: ASLR Enabled" % app
                else:
                  print "%s: ASLR Not Enabled" % app

                # DEP check
                if ae.checkApplicationForDep(pe):
                  print "%s: DEP Enabled" % app
                else:
                  print "%s: DEP Not Enabled" % app

            except pefile.PEFormatError:
                print "'%s' is not a PE file!" %app
        else:
            print "File '%s' not found!" % app

    # Check for null page mapping
    print "Able to map null page: %s" % ae.checkNullPageMapping()

    # Check for legacy BIOS or UEFI mode
    print "Firmware Mode: %s" % ae.checkFirmwareType()

    # Check for hardware anti-exploitation features
    hardware_support = ae.checkHardwareSupport()
    for key in hardware_support:
        print "%s: %s" % (key, hardware_support[key])
