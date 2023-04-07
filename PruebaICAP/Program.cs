namespace PruebaICAP
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Prueba");
            using var icap = new IcapClient("localhost");
            icap.Scan("prueba.txt");
        }
    }
}