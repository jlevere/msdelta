using System.Reflection;

namespace ManagedFixture {
    public sealed class Resources {
        public string[] Names() {
            return Assembly.GetExecutingAssembly().GetManifestResourceNames();
        }
    }
}