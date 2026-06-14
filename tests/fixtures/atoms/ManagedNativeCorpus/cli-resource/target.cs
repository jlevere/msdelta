using System.Reflection;

namespace ManagedFixture {
    public sealed class Resources {
        public string[] Names() {
            string[] names = Assembly.GetExecutingAssembly().GetManifestResourceNames();
            System.Array.Sort(names);
            return names;
        }
    }
}