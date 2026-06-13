namespace ManagedFixture {
    public sealed class Calculator {
        public int Compute(int a, int b) {
            return Helper(a) + b;
        }

        private static int Helper(int value) {
            return value + 3;
        }
    }
}