namespace ManagedFixture {
    public static class StaticConstructorTokens {
        private static int value;
        private static int scale;

        static StaticConstructorTokens() {
            value = Helper(5);
            scale = Added(7);
        }

        public static int Get() {
            return value * scale;
        }

        private static int Added(int input) {
            return input - 2;
        }

        private static int Helper(int input) {
            return input + 4;
        }
    }
}