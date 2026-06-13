using System;

namespace ManagedFixture {
    [AttributeUsage(AttributeTargets.All, AllowMultiple = true)]
    public sealed class MarkerAttribute : Attribute {
        public MarkerAttribute(string name) {
            Name = name;
        }

        public string Name { get; private set; }
        public int Version;
    }

    [Marker("source", Version = 1)]
    public sealed class Annotated {
        [Marker("source-method", Version = 2)]
        public void Run() {
        }
    }
}