namespace ManagedFixture {
    public sealed class ConstructorString {
        private readonly string text;

        public ConstructorString() {
            text = "target constructor string with more data";
        }

        public string Text {
            get { return text.ToUpperInvariant(); }
        }
    }
}