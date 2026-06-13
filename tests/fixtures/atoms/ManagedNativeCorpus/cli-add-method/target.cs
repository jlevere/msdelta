namespace ManagedFixture {
    public sealed class Calculator {
        public int Compute(int a, int b) {
            return Added(Helper(a), b);
        }

        private static int Helper(int value) {
            return value + 5;
        }

        private static int Added(int left, int right) {
            return (left * 2) + right;
        }
    }
}