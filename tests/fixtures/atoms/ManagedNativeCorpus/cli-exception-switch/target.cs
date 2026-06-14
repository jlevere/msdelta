using System;

namespace ManagedFixture {
    public sealed class ControlFlow {
        public int Classify(int value) {
            int result = 0;
            try {
                switch (value) {
                    case 0:
                        result = 11;
                        break;
                    case 1:
                        result = 21;
                        break;
                    case 2:
                    case 3:
                        result = 40 + value;
                        break;
                    default:
                        result = 120 / value;
                        break;
                }
            } catch (DivideByZeroException) {
                result = -2;
            } finally {
                result += 1;
            }
            return result;
        }
    }
}