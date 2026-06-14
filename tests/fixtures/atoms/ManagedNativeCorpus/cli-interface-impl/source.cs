namespace ManagedFixture {
    public interface IWorker {
        int Work(int value);
    }

    public sealed class Worker : IWorker {
        public int Work(int value) {
            return value + 1;
        }
    }
}