using System;

namespace ManagedFixture {
    public interface IWorker {
        int Work(int value);
    }

    public interface INamed {
        string Name { get; }
    }

    public sealed class Worker : IWorker, INamed, IComparable<Worker> {
        public string Name {
            get { return "worker"; }
        }

        public int Work(int value) {
            return value + Name.Length;
        }

        int IComparable<Worker>.CompareTo(Worker other) {
            if (other == null) {
                return 1;
            }
            return Name.Length - other.Name.Length;
        }
    }
}