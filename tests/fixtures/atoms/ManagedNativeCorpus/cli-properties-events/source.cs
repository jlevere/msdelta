using System;

namespace ManagedFixture {
    public sealed class Notifier {
        public event EventHandler Changed;
        private int count;

        public int Count {
            get { return count; }
            set {
                count = value;
                OnChanged();
            }
        }

        private void OnChanged() {
            EventHandler handler = Changed;
            if (handler != null) {
                handler(this, EventArgs.Empty);
            }
        }
    }
}