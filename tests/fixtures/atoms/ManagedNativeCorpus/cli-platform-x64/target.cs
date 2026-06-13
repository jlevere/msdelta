using System;

namespace ManagedFixture {
    public sealed class PlatformCase {
        public long PointerScaled(long value) {
            return (value * 2) + IntPtr.Size;
        }
    }
}