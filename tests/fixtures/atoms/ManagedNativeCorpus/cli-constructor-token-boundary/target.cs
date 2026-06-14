namespace ManagedFixture {
    public sealed class ConstructorTokens {
        private int value;
        private int extra;

        public ConstructorTokens(int seed) {
            value = Helper(seed);
            extra = Added(seed);
        }

        public int Value() {
            return value + extra;
        }

        private static int Added(int input) {
            return input * 2;
        }

        private static int Helper(int input) {
            return input + 3;
        }
    }
}