using System;

namespace ManagedFixture {
    public sealed class Entry {
        public string Message() {
            return "target-beta-with-longer-text";
        }

        public int Value() {
            return Message().Length + 11;
        }
    }
}