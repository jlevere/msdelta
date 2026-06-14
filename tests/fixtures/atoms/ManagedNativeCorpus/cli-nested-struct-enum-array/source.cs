namespace ManagedFixture {
    public enum Mode : short {
        Source = 1,
        Shared = 2
    }

    public struct Point {
        public int X;
        public int Y;
    }

    public sealed class Shape {
        public Point[] Points() {
            return new Point[] { new Point { X = 1, Y = 2 } };
        }
    }
}