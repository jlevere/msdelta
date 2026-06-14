using System;

namespace ManagedFixture {
    public enum Mode : short {
        Source = 1,
        Shared = 2,
        Target = 3
    }

    public struct Point {
        public int X;
        public int Y;
        public int Z;
    }

    public sealed class Shape {
        public enum Quality : byte {
            Low = 1,
            High = 2
        }

        public Tuple<Mode, Point[]> Build() {
            Point[] points = new Point[] {
                new Point { X = 1, Y = 2, Z = 3 },
                new Point { X = 5, Y = 8, Z = 13 }
            };
            return Tuple.Create(Mode.Target, points);
        }
    }
}