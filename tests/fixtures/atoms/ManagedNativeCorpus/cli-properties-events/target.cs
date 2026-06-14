using System;

namespace ManagedFixture {
    public sealed class Notifier {
        public event EventHandler Changed;
        public event EventHandler Reset;
        private int count;

        public int Count {
            get { return count; }
            set {
                count = value;
                OnChanged();
            }
        }

        public string Name { get; set; }

        public void Clear() {
            count = 0;
            EventHandler handler = Reset;
            if (handler != null) {
                handler(this, EventArgs.Empty);
            }
            OnChanged();
        }

        private void OnChanged() {
            EventHandler handler = Changed;
            if (handler != null) {
                handler(this, EventArgs.Empty);
            }
        }
    }
}