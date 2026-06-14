namespace ManagedFixture {
    public sealed class ConstructorString {
        private readonly string text;

        public ConstructorString() {
            text = "source constructor string";
        }

        public string Text {
            get { return text; }
        }
    }
}