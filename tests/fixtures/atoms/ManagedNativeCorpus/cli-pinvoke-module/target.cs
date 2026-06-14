using System.Runtime.InteropServices;

namespace ManagedFixture {
    internal static class NativeMethods {
        [DllImport("kernel32.dll")]
        internal static extern uint GetTickCount();

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool QueryPerformanceCounter(out long value);
    }

    public sealed class NativeUser {
        public long Read() {
            long value;
            if (NativeMethods.QueryPerformanceCounter(out value)) {
                return value;
            }
            return NativeMethods.GetTickCount();
        }
    }
}