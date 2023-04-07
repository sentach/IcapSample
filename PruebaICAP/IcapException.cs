using System.Runtime.Serialization;

namespace PruebaICAP
{
    [Serializable]
    public class IcapException : Exception
    {
        public IcapException()
        {
        }

        public IcapException(string? message) : base(message)
        {
        }

        public IcapException(string? message, Exception? innerException) : base(message, innerException)
        {
        }

        protected IcapException(SerializationInfo info, StreamingContext context) : base(info, context)
        {
        }
    }
}