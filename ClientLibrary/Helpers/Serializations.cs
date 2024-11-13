using System.Text.Json;

namespace ClientLibrary.Helpers
{
    public static class Serializations
    {
        public static string SerializeObj<T>(T obj) => JsonSerializer.Serialize(obj);
        public static T DeserializeJsonString<T>(string json) => JsonSerializer.Deserialize<T>(json);
        public static IList<T> DeserializeJsonStringList<T>(string json) => JsonSerializer.Deserialize<IList<T>>(json);
    }
}
