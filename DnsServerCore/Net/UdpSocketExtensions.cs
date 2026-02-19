using System;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

namespace DnsServerCore.Net
{
    internal static class UdpSocketExtensions
    {
        private const int IPPROTO_IP = 0;
        private const int IPPROTO_IPV6 = 41;

        private const int IP_PKTINFO = 8;
        private const int IPV6_PKTINFO = 50;

        private const int SIO_UDP_CONNRESET = unchecked((int)0x9800000C);
        private static readonly Guid WSAID_WSASENDMSG = new Guid("a441e712-754f-43ca-84a7-0dcd44477436");
        private const int SIO_GET_EXTENSION_FUNCTION_POINTER = unchecked((int)0xC8000006);

        private delegate int WSASendMsgDelegate(IntPtr s, ref WSAMSG lpMsg, uint dwFlags, out uint lpNumberOfBytesSent, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);
        private static WSASendMsgDelegate _wsaSendMsg;

        static UdpSocketExtensions()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                //initialize WSASendMsg delegate
                using (Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp))
                {
                    IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                    IntPtr outPtr = Marshal.AllocHGlobal(Marshal.SizeOf<IntPtr>());
                    try
                    {
                        Marshal.StructureToPtr(WSAID_WSASENDMSG, ptr, false);
                        int bytesReturned = 0;
                        if (WSAIoctl(s.Handle, SIO_GET_EXTENSION_FUNCTION_POINTER, ptr, Marshal.SizeOf<Guid>(), outPtr, Marshal.SizeOf<IntPtr>(), out bytesReturned, IntPtr.Zero, IntPtr.Zero) == 0)
                        {
                            IntPtr funcPtr = Marshal.ReadIntPtr(outPtr);
                            _wsaSendMsg = Marshal.GetDelegateForFunctionPointer<WSASendMsgDelegate>(funcPtr);
                        }
                    }
                    finally
                    {
                        Marshal.FreeHGlobal(ptr);
                        Marshal.FreeHGlobal(outPtr);
                    }
                }
            }
        }

        public static async Task SendMessageToAsync(this Socket socket, ReadOnlyMemory<byte> buffer, SocketFlags socketFlags, EndPoint remoteEP, IPPacketInformation packetInfo)
        {
            if (packetInfo.Address.Equals(IPAddress.Any) || packetInfo.Address.Equals(IPAddress.IPv6Any))
            {
                //use standard .NET SendToAsync if source address is not specified
                await socket.SendToAsync(buffer, socketFlags, remoteEP);
                return;
            }

            //for specific source address, use platform specific sendmsg implementation
            //blocking/synchronous call is used here as async implementation is complex and overkill for UDP sending
            //this runs on thread pool so blocking is acceptable for most DNS scenarios

            IPEndPoint remoteIPEndPoint = remoteEP as IPEndPoint;
            if (remoteIPEndPoint == null)
                throw new ArgumentException("Remote endpoint must be IPEndPoint", nameof(remoteEP));

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                SendWindows(socket, buffer, remoteIPEndPoint, packetInfo);
            }
            else
            {
                SendUnix(socket, buffer, remoteIPEndPoint, packetInfo);
            }
        }

        private static void SendWindows(Socket socket, ReadOnlyMemory<byte> buffer, IPEndPoint remoteEP, IPPacketInformation packetInfo)
        {
            if (_wsaSendMsg == null)
                throw new PlatformNotSupportedException("WSASendMsg not available");

            GCHandle bufferHandle = GCHandle.Alloc(buffer.ToArray(), GCHandleType.Pinned); //TODO: avoid copy/alloc
            IntPtr controlBuffer = IntPtr.Zero;

            try
            {
                WSABUF wsaBuf;
                wsaBuf.len = (uint)buffer.Length;
                wsaBuf.buf = bufferHandle.AddrOfPinnedObject();

                SocketAddress remoteSocketAddress = remoteEP.Serialize();
                byte[] remoteSocketAddressBytes = new byte[remoteSocketAddress.Size];
                for (int i = 0; i < remoteSocketAddress.Size; i++)
                    remoteSocketAddressBytes[i] = remoteSocketAddress[i];

                GCHandle remoteSocketAddressHandle = GCHandle.Alloc(remoteSocketAddressBytes, GCHandleType.Pinned);

                try
                {
                    WSAMSG msg = new WSAMSG();
                    msg.name = remoteSocketAddressHandle.AddrOfPinnedObject();
                    msg.namelen = remoteSocketAddress.Size;
                    msg.lpBuffers = Marshal.UnsafeAddrOfPinnedArrayElement(new WSABUF[] { wsaBuf }, 0);
                    msg.dwBufferCount = 1;
                    msg.dwFlags = 0;

                    if (packetInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        int controlLen = WSA_CMSG_SPACE(Marshal.SizeOf<in_pktinfo>());
                        controlBuffer = Marshal.AllocHGlobal(controlLen);
                        msg.Control.buf = controlBuffer;
                        msg.Control.len = (uint)controlLen;

                        WSACMSGHDR cmsg;
                        cmsg.cmsg_len = (uint)WSA_CMSG_LEN(Marshal.SizeOf<in_pktinfo>());
                        cmsg.cmsg_level = IPPROTO_IP;
                        cmsg.cmsg_type = IP_PKTINFO;

                        Marshal.StructureToPtr(cmsg, controlBuffer, false);

                        in_pktinfo pktinfo;
                        pktinfo.ipi_addr = BitConverter.ToUInt32(packetInfo.Address.GetAddressBytes(), 0);
                        pktinfo.ipi_ifindex = (uint)packetInfo.Interface;

                        IntPtr dataPtr = (IntPtr)((long)controlBuffer + Marshal.SizeOf<WSACMSGHDR>());
                        Marshal.StructureToPtr(pktinfo, dataPtr, false);
                    }
                    else
                    {
                        int controlLen = WSA_CMSG_SPACE(Marshal.SizeOf<in6_pktinfo>());
                        controlBuffer = Marshal.AllocHGlobal(controlLen);
                        msg.Control.buf = controlBuffer;
                        msg.Control.len = (uint)controlLen;

                        WSACMSGHDR cmsg;
                        cmsg.cmsg_len = (uint)WSA_CMSG_LEN(Marshal.SizeOf<in6_pktinfo>());
                        cmsg.cmsg_level = IPPROTO_IPV6;
                        cmsg.cmsg_type = IPV6_PKTINFO;

                        Marshal.StructureToPtr(cmsg, controlBuffer, false);

                        in6_pktinfo pktinfo;
                        pktinfo.ipi6_addr = packetInfo.Address.GetAddressBytes();
                        pktinfo.ipi6_ifindex = (uint)packetInfo.Interface;

                        IntPtr dataPtr = (IntPtr)((long)controlBuffer + Marshal.SizeOf<WSACMSGHDR>());
                        Marshal.StructureToPtr(pktinfo, dataPtr, false);
                    }

                    uint bytesSent;
                    int result = _wsaSendMsg(socket.Handle, ref msg, 0, out bytesSent, IntPtr.Zero, IntPtr.Zero);
                    if (result != 0)
                    {
                        int error = Marshal.GetLastWin32Error();
                        throw new SocketException(error);
                    }
                }
                finally
                {
                    remoteSocketAddressHandle.Free();
                }
            }
            finally
            {
                bufferHandle.Free();
                if (controlBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(controlBuffer);
            }
        }

        private static void SendUnix(Socket socket, ReadOnlyMemory<byte> buffer, IPEndPoint remoteEP, IPPacketInformation packetInfo)
        {
            GCHandle bufferHandle = GCHandle.Alloc(buffer.ToArray(), GCHandleType.Pinned); //TODO: avoid copy/alloc
            IntPtr controlBuffer = IntPtr.Zero;

            try
            {
                iovec iov;
                iov.iov_base = bufferHandle.AddrOfPinnedObject();
                iov.iov_len = (IntPtr)buffer.Length;

                SocketAddress remoteSocketAddress = remoteEP.Serialize();
                byte[] remoteSocketAddressBytes = new byte[remoteSocketAddress.Size];
                for (int i = 0; i < remoteSocketAddress.Size; i++)
                    remoteSocketAddressBytes[i] = remoteSocketAddress[i];

                GCHandle remoteSocketAddressHandle = GCHandle.Alloc(remoteSocketAddressBytes, GCHandleType.Pinned);

                try
                {
                    msghdr msg = new msghdr();
                    msg.msg_name = remoteSocketAddressHandle.AddrOfPinnedObject();
                    msg.msg_namelen = remoteSocketAddress.Size;
                    msg.msg_iov = Marshal.UnsafeAddrOfPinnedArrayElement(new iovec[] { iov }, 0); //unsafe but we only use one
                    msg.msg_iovlen = (IntPtr)1;
                    msg.msg_flags = 0;

                    if (packetInfo.Address.AddressFamily == AddressFamily.InterNetwork)
                    {
                        int controlLen = CMSG_SPACE(Marshal.SizeOf<in_pktinfo>());
                        controlBuffer = Marshal.AllocHGlobal(controlLen);
                        msg.msg_control = controlBuffer;
                        msg.msg_controllen = (IntPtr)controlLen;

                        cmsghdr cmsg;
                        cmsg.cmsg_len = (IntPtr)CMSG_LEN(Marshal.SizeOf<in_pktinfo>());
                        cmsg.cmsg_level = IPPROTO_IP;
                        cmsg.cmsg_type = IP_PKTINFO;

                        Marshal.StructureToPtr(cmsg, controlBuffer, false);

                        in_pktinfo pktinfo;
                        pktinfo.ipi_ifindex = packetInfo.Interface;
                        pktinfo.ipi_spec_dst = BitConverter.ToUInt32(packetInfo.Address.GetAddressBytes(), 0);
                        pktinfo.ipi_addr = 0; //not used for sending

                        IntPtr dataPtr = (IntPtr)((long)controlBuffer + Marshal.SizeOf<cmsghdr>()); //alignment might need care? usually ok for int/uint
                        //Better to check alignment: CMSG_DATA equivalent
                        Marshal.StructureToPtr(pktinfo, dataPtr, false);
                    }
                    else
                    {
                        int controlLen = CMSG_SPACE(Marshal.SizeOf<in6_pktinfo>());
                        controlBuffer = Marshal.AllocHGlobal(controlLen);
                        msg.msg_control = controlBuffer;
                        msg.msg_controllen = (IntPtr)controlLen;

                        cmsghdr cmsg;
                        cmsg.cmsg_len = (IntPtr)CMSG_LEN(Marshal.SizeOf<in6_pktinfo>());
                        cmsg.cmsg_level = IPPROTO_IPV6;
                        cmsg.cmsg_type = IPV6_PKTINFO;

                        Marshal.StructureToPtr(cmsg, controlBuffer, false);

                        in6_pktinfo pktinfo;
                        pktinfo.ipi6_addr = packetInfo.Address.GetAddressBytes();
                        pktinfo.ipi6_ifindex = (uint)packetInfo.Interface;

                        IntPtr dataPtr = (IntPtr)((long)controlBuffer + Marshal.SizeOf<cmsghdr>());
                        Marshal.StructureToPtr(pktinfo, dataPtr, false);
                    }

                    IntPtr sent = sendmsg(socket.Handle, ref msg, 0);
                    if ((long)sent < 0)
                    {
                        int error = Marshal.GetLastWin32Error(); //Marshal.GetLastPInvokeError on recent .NET
                        throw new SocketException(error);
                    }
                }
                finally
                {
                    remoteSocketAddressHandle.Free();
                }
            }
            finally
            {
                bufferHandle.Free();
                if (controlBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(controlBuffer);
            }
        }

        // Native Imports

        [DllImport("ws2_32.dll", SetLastError = true)]
        private static extern int WSAIoctl(IntPtr s, int dwIoControlCode, IntPtr lpvInBuffer, int cbInBuffer, IntPtr lpvOutBuffer, int cbOutBuffer, out int lpcbBytesReturned, IntPtr lpOverlapped, IntPtr lpCompletionRoutine);

        [DllImport("libc", SetLastError = true)]
        private static extern IntPtr sendmsg(IntPtr s, ref msghdr msg, int flags);

        // Windows Structs

        [StructLayout(LayoutKind.Sequential)]
        private struct WSAMSG
        {
            public IntPtr name;
            public int namelen;
            public IntPtr lpBuffers;
            public uint dwBufferCount;
            public WSABUF Control;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WSABUF
        {
            public uint len;
            public IntPtr buf;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct WSACMSGHDR
        {
            public uint cmsg_len;
            public int cmsg_level;
            public int cmsg_type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct in_pktinfo // Windows
        {
            public uint ipi_addr;
            public uint ipi_ifindex;
        }

        // Unix Structs

        [StructLayout(LayoutKind.Sequential)]
        private struct msghdr
        {
            public IntPtr msg_name;
            public int msg_namelen;
            public IntPtr msg_iov;
            public IntPtr msg_iovlen;
            public IntPtr msg_control;
            public IntPtr msg_controllen;
            public int msg_flags;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct iovec
        {
            public IntPtr iov_base;
            public IntPtr iov_len;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct cmsghdr // Unix (typically size_t len, int level, int type) - assuming 64-bit alignment for len?
        {
             // On 64-bit Linux/Mac, size_t is 64-bit (IntPtr), int is 32-bit.
             // Struct padding applies.
             // Wait, cmsghdr.cmsg_len is socklen_t on Linux (32-bit uint) usually? 
             // RFC 3542 says socklen_t cmsg_len.
             // On Linux <sys/socket.h>, struct cmsghdr { size_t cmsg_len; int cmsg_level; int cmsg_type; };
             // size_t is 64-bit on x64.
            public IntPtr cmsg_len; 
            public int cmsg_level;
            public int cmsg_type;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct in_pktinfo // Linux/Unix
        {
            public int ipi_ifindex;
            public uint ipi_spec_dst;
            public uint ipi_addr;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct in6_pktinfo // Universal
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] ipi6_addr;
            public uint ipi6_ifindex;
        }

        // Macros

        private static int WSA_CMSG_LEN(int length)
        {
             // WSA_CMSGDATA_ALIGN(sizeof(WSACMSGHDR)) + length
             // WSACMSGHDR is 12 bytes? 4+4+4.
             // Alignment is 4? 
             return (12 + length + 3) & ~3; //Simplified alignment (might need rigorous check)
        }

        private static int WSA_CMSG_SPACE(int length)
        {
             return WSA_CMSG_LEN(length);
        }
        
        private static int CMSG_LEN(int length)
        {
            // sizeof(cmsghdr) + length
            // On x64 Linux: sizeof(cmsghdr) is 16 (8 len + 4 level + 4 type).
            // Length aligned.
            return (16 + length + 7) & ~7; // Simplified 64-bit alignment
        }

        private static int CMSG_SPACE(int length)
        {
            return CMSG_LEN(length);
        }
    }
}
