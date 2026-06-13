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

    [Marker("target", Version = 3)]
    [Marker("second", Version = 4)]
    public sealed class Annotated {
        [Marker("target-method", Version = 5)]
        public void Run() {
        }
    }
}