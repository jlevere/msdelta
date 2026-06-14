using System;

namespace ManagedFixture {
    public sealed class ControlFlow {
        public int Classify(int value) {
            try {
                switch (value) {
                    case 0:
                        return 10;
                    case 1:
                        return 20;
                    default:
                        return 30 / value;
                }
            } catch (DivideByZeroException) {
                return -1;
            }
        }
    }
}