using System;
using System.Runtime.InteropServices;

internal static class WreqNative
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct Request
    {
        public IntPtr ProxyUrl, Url, Method, Body;
        public int Timeout, IdleTimeout;
        public IntPtr Headers, HeaderOrder, TlsProfile, Id, Cookies;
        [MarshalAs(UnmanagedType.I1)] public bool CloseIdleConnections;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct Response
    {
        public IntPtr Location, Protocol, Body;
        public int BodyLength;
        public IntPtr ContentType;
        public int Status;
        public IntPtr Headers, RequestUrl;
    }

    [DllImport("wreq", CallingConvention = CallingConvention.Cdecl)]
    internal static extern int wreq_execute(ref Request request, out IntPtr response, out IntPtr error);

    [DllImport("wreq", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void wreq_response_free(IntPtr response);

    [DllImport("wreq", CallingConvention = CallingConvention.Cdecl)]
    internal static extern void wreq_error_free(IntPtr error);
}
