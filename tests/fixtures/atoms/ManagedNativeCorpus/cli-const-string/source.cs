using System;

namespace ManagedFixture {
    public sealed class Entry {
        public string Message() {
            return "source-alpha";
        }

        public int Value() {
            return Message().Length + 7;
        }
    }
}