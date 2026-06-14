namespace ManagedFixture {
    public sealed class ConstructorTokens {
        private int value;

        public ConstructorTokens(int seed) {
            value = Helper(seed);
        }

        public int Value() {
            return value;
        }

        private static int Helper(int input) {
            return input + 1;
        }
    }
}