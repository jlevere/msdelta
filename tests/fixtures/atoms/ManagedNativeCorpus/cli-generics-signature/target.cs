using System;
using System.Collections.Generic;

namespace ManagedFixture {
    public sealed class Box<T> {
        private readonly T value;

        public Box(T value) {
            this.value = value;
        }

        public U Convert<U>(Func<T, U> map) {
            return map(value);
        }

        public T Value {
            get { return value; }
        }
    }

    public static class UseBox {
        public static Dictionary<string, List<int>> Make(Box<string> box) {
            return new Dictionary<string, List<int>> {
                { box.Value, new List<int> { 1, 2, 3 } }
            };
        }
    }
}