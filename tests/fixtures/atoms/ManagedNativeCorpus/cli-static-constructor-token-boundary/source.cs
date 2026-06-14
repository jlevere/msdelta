namespace ManagedFixture {
    public static class StaticConstructorTokens {
        private static int value;

        static StaticConstructorTokens() {
            value = Helper(5);
        }

        public static int Get() {
            return value;
        }

        private static int Helper(int input) {
            return input + 1;
        }
    }
}