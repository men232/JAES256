using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace JAES_Test
{
    class Program
    {
        static void Main(string[] args)
        {
            JAES256.JAES256 jaes = new JAES256.JAES256("salt");

            var t = jaes.Encrypt("hello", "key");
            var result = jaes.Decrypt(t, "key");

            Console.WriteLine(result);
            Console.ReadKey();
        }
    }
}
