using System;

namespace ManagedFixture {
    public sealed class Box<T> {
        private readonly T value;

        public Box(T value) {
            this.value = value;
        }

        public T Identity(T input) {
            return input;
        }

        public T Value {
            get { return value; }
        }
    }

    public static class UseBox {
        public static string Join(Box<string> box, string suffix) {
            return box.Value + suffix;
        }
    }
}