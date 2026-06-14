using System.Runtime.InteropServices;

namespace ManagedFixture {
    internal static class NativeMethods {
        [DllImport("kernel32.dll")]
        internal static extern uint GetTickCount();
    }

    public sealed class NativeUser {
        public uint Read() {
            return NativeMethods.GetTickCount();
        }
    }
}