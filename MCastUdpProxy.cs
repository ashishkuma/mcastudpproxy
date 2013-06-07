//
//      Copyright (C) 2012-2013 Viktor PetroFF
//
//  This Program is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2, or (at your option)
//  any later version.
//
//  This Program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with MCastUdpProxy; see the file COPYING.  If not, write to
//  the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
//  http://www.gnu.org/copyleft/gpl.html
//
//

using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Configuration;
using System.ServiceProcess;


namespace MCastUdpProxy
{
    class MProxyProgram : ServiceBase
    {
        [DllImport("Kernel32.dll")]
        public static extern int SetStdHandle(int device, IntPtr handle);

        private static FileStream _streamRedirect;
        private static StreamWriter _writerRedirect;

        private const int DEFAULT_PORT = 1234;

        private IgmpProxy _proxyIGMP;
        private MulticastProxy _proxyMCast;
        private uint _uiCount;


        static MProxyProgram()
        {
            Directory.SetCurrentDirectory(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location));

            if (!ConfigurationManager.AppSettings.HasKeys())
            {
                Configuration config = ConfigurationManager.OpenExeConfiguration(ConfigurationUserLevel.None);

                config.AppSettings.Settings.Add("ExternalIP", IPAddress.Loopback.ToString() + ':' + DEFAULT_PORT.ToString());
                config.AppSettings.Settings.Add("InternalIP", IPAddress.Loopback.ToString());
                config.AppSettings.Settings.Add("MulticastAddressScope", "224.1.1.1-239.250.250.250");
                config.AppSettings.Settings.Add("HostRedirection", IPAddress.Any.ToString() + "=" + IPAddress.Any.ToString());
                config.AppSettings.Settings.Add("PriorityHigh", bool.FalseString);
                config.AppSettings.Settings.Add("DebugLog", bool.FalseString);
                config.Save();
            }
        }

        public MProxyProgram()
        {
            Assembly assem = Assembly.GetExecutingAssembly();
            AssemblyName assemName = assem.GetName();

            this.ServiceName = assemName.Name;
            this.CanStop = true;
            //this.CanPauseAndContinue = true;
            //this.AutoLog = true;

            bool bDebug = false;
            string strAppParam;
            if (null != (strAppParam = ConfigurationManager.AppSettings["DebugLog"]))
            {
                bDebug = bool.Parse(strAppParam);
            }

            Log.DebugEnable = bDebug;
        }

        private static int Main(string[] args)
        {
            ShowVersion();

            if (args.Length > 2)
            {
                return ShowUsage();
            }

            string strExtEndPoint = string.Empty;
            string strIntEndPoint = string.Empty;

            if (0 == args.Length)
            {
                ShowUsage();

                string strAppParam;
                if (null != (strAppParam = ConfigurationManager.AppSettings["ExternalIP"]))
                {
                    strExtEndPoint = strAppParam;
                }

                if (null != (strAppParam = ConfigurationManager.AppSettings["InternalIP"]))
                {
                    strIntEndPoint = strAppParam;
                }
            }
            else
            {
                int ndx = 0;
                strExtEndPoint = args[ndx++];
                if (args.Length > 1)
                {
                    strIntEndPoint = args[ndx++];
                }
            }

            if ("/service-install" == strExtEndPoint)
            {
                System.Configuration.Install.TransactedInstaller ti = null;
                ti = new System.Configuration.Install.TransactedInstaller();
                ti.Installers.Add(new ProjectInstaller());
                ti.Context = new System.Configuration.Install.InstallContext("", null);
                string path = Assembly.GetExecutingAssembly().Location;
                ti.Context.Parameters["assemblypath"] = path;
                ti.Install(new Hashtable());
            }
            else if ("/service-uninstall" == strExtEndPoint)
            {
                System.Configuration.Install.TransactedInstaller ti = null;
                ti = new System.Configuration.Install.TransactedInstaller();
                ti.Installers.Add(new ProjectInstaller());
                ti.Context = new System.Configuration.Install.InstallContext("", null);
                string path = Assembly.GetExecutingAssembly().Location;
                ti.Context.Parameters["assemblypath"] = path;
                ti.Uninstall(null);
            }
            else if ("/service-run" == strExtEndPoint)
            {
                RedirectStd();
                System.ServiceProcess.ServiceBase.Run(new MProxyProgram());
            }
            else
            {
                MProxyProgram mproxy = new MProxyProgram();
                int rc = mproxy.Start(strExtEndPoint, strIntEndPoint, false);

                if (0 != rc)
                {
                    return rc;
                }

                Console.WriteLine();
                Console.WriteLine("Press any key to exit.");
                Console.WriteLine();

                while (Console.KeyAvailable == false)
                {
                    mproxy.Loop(250);
                }

                mproxy.Stop();
            }

            return 0;
        }

        private static void ShowVersion()
        {
            Assembly assem = Assembly.GetExecutingAssembly();
            AssemblyName assemName = assem.GetName();

            Console.WriteLine("{0} version {1}", assemName.Name, assemName.Version.ToString(3));
            Console.WriteLine("Multicast to unicast proxy.");
            Console.WriteLine("This software developed by Viktor PetroFF (aka ViPetroFF).");
            Console.WriteLine();
        }

        private static int ShowUsage()
        {
            Console.WriteLine();
            Console.WriteLine("Forwards IGMP traffic between external and internal interfaces.");
            Console.WriteLine("And retransmits UDP multicast traffic from external interface to" +
                " unicast destination endpoint of the internal interface.");
            Console.WriteLine();
            Console.WriteLine("Usage: {0} externalIP[:Port] internalIP[+Port|:Port]",
                Path.GetFileName(Assembly.GetExecutingAssembly().Location));
            Console.WriteLine("Service: [/service-install|/service-uninstall|/service-run]");

            return 1;
        }

        private static void RedirectStd()
        {
            if (File.Exists("log.txt"))
            {
                File.Delete("old.log.txt");
                File.Move("log.txt", "old.log.txt");
            }

            _streamRedirect = new FileStream("log.txt", FileMode.Create);
            _writerRedirect = new StreamWriter(_streamRedirect);
            _writerRedirect.AutoFlush = true;
            Console.SetOut(_writerRedirect);
            Console.SetError(_writerRedirect);
#if FALSE
            int status;
            IntPtr handle = _streamRedirect.SafeFileHandle.DangerousGetHandle();
            status = SetStdHandle(-11, handle); // set stdout
            // Check status as needed
            //Console.WriteLine("status stdout = {0}", status);
            status = SetStdHandle(-12, handle); // set stderr
            // Check status as needed
            //Console.WriteLine("status stderr = {0}", status);
#endif // FALSE
            Log.EnableFileLog = true;

            ShowVersion();
        }

        protected int Start(string strExtEndPoint, string strIntEndPoint, bool bIsService)
        {
            IPAddress externAddress;
            int iSourcePort = 0;

            int ndxx = strExtEndPoint.IndexOf(':');
            if (ndxx < 0)
            {
                externAddress = (0 == strExtEndPoint.Length) ? IPAddress.Loopback : IPAddress.Parse(strExtEndPoint);
            }
            else
            {
                externAddress = IPAddress.Parse(strExtEndPoint.Substring(0, ndxx));
                iSourcePort = int.Parse(strExtEndPoint.Substring(ndxx + 1));
            }

            IPAddress internAddress;
            int iPlusPort = 0;
            int iDestinationPort = 0;

            ndxx = strIntEndPoint.IndexOf('+');
            if (ndxx < 0)
            {
                ndxx = strIntEndPoint.IndexOf(':');
                if (ndxx < 0)
                {
                    internAddress = (0 == strExtEndPoint.Length) ? IPAddress.Loopback : IPAddress.Parse(strIntEndPoint);
                }
                else
                {
                    internAddress = IPAddress.Parse(strIntEndPoint.Substring(0, ndxx));
                    iDestinationPort = int.Parse(strIntEndPoint.Substring(ndxx + 1));
                }
            }
            else
            {
                internAddress = IPAddress.Parse(strIntEndPoint.Substring(0, ndxx));
                iPlusPort = int.Parse(strIntEndPoint.Substring(ndxx + 1));
            }

            if (externAddress.Equals(internAddress))
            {
                Console.WriteLine("External and internal interfaces is same.");
                return 2;
            }

            bool PriorityHigh = false;
            string strVal;
            if (null != (strVal = ConfigurationManager.AppSettings["PriorityHigh"]))
            {
                PriorityHigh = bool.Parse(strVal);
            }

            if (PriorityHigh)
            {
                Process.GetCurrentProcess().PriorityClass = ProcessPriorityClass.High;
            }

            _proxyIGMP = new IgmpProxy(externAddress, internAddress, bIsService);
            _proxyMCast = new MulticastProxy(
                                            _proxyIGMP,
                                            externAddress,
                                            internAddress,
                                            iSourcePort,
                                            iPlusPort,
                                            iDestinationPort);

            _proxyIGMP.StartIGMPProxy();

            return 0;
        }

        protected void Stop()
        {
            _proxyMCast.Close();
            _proxyIGMP.Close();
        }

        protected void Loop(int millisecondsTimeout)
        {
            Thread.Sleep(millisecondsTimeout);

            _proxyIGMP.WriteLogMessage();

            if (0 == (++_uiCount % 4))
            {
                _proxyMCast.WriteLogMessage();
            }
        }

        protected override void OnStart(string[] args)
        {
            string strExtEndPoint = string.Empty;
            string strIntEndPoint = string.Empty;

            if (args.Length > 1)
            {
                int ndx = 1;
                strExtEndPoint = args[ndx++];
                if (args.Length > 1)
                {
                    strIntEndPoint = args[ndx++];
                }
            }
            else
            {
                string strAppParam;
                if (null != (strAppParam = ConfigurationManager.AppSettings["ExternalIP"]))
                {
                    strExtEndPoint = strAppParam;
                }

                if (null != (strAppParam = ConfigurationManager.AppSettings["InternalIP"]))
                {
                    strIntEndPoint = strAppParam;
                }
            }

            int rc = this.Start(strExtEndPoint, strIntEndPoint, true);

            if (0 != rc)
            {
                string msg = string.Format("Failed service start, exit code {0}.", rc);
                Log.Error(msg);
                throw new Exception(msg);
            }
        }

        protected override void OnStop()
        {
            this.Stop();
        }

        private void InitializeComponent()
        {
            // 
            // MProxyProgram
            // 
            this.AutoLog = false;
            //this.ServiceName = "MCastUdpProxy";

            Assembly assem = Assembly.GetExecutingAssembly();
            AssemblyName assemName = assem.GetName();
            this.ServiceName = assemName.Name;
        }
    }

    static class Log
    {
        private static int _iPadSize = 75;
        private static int _iProgressHigh = 0;
        private static bool _bIsFileLog = true;
        private static bool _bDebugEnable = false;

        public static bool EnableFileLog
        {
            get { return _bIsFileLog; }
            set { _bIsFileLog = value; }
        }

        public static bool DebugEnable
        {
            get { return _bDebugEnable; }
            set { _bDebugEnable = value; }
        }

        static Log()
        {
            try
            {
                _iPadSize = Console.BufferWidth - 1;
                _bIsFileLog = false;
            }
            catch
            {
            }
        }

        private static void WriteLine(string msg, TextWriter writer)
        {
            DateTime timeNow = DateTime.UtcNow.ToLocalTime();
            string date = timeNow.ToShortDateString();

            string message = string.Format("{0}> {1}", timeNow.ToShortTimeString(), msg);

            if (_bIsFileLog)
            {
                writer.WriteLine(message);
            }
            else
            {
                lock (typeof(Log))
                {
                    Console.SetCursorPosition(0, Console.CursorTop - _iProgressHigh);
                    writer.WriteLine(message.PadRight(_iPadSize));

                    for (int ndx = 0; ndx < _iProgressHigh; ndx++)
                    {
                        writer.WriteLine(string.Empty.PadLeft(_iPadSize));
                    }
                }
            }
        }

        public static int PadSize
        {
            get { return _iPadSize - 16; }
        }

        public static void Debug(string msg)
        {
            if (DebugEnable)
            {
                WriteLine(msg, Console.Out);
            }
        }

        public static void Message(string msg)
        {
            WriteLine(msg, Console.Out);
        }

        public static void Error(string msg)
        {
            WriteLine(msg, Console.Error);
        }

        public static void MessageProgress(string msg, int ID)
        {
            if (!_bIsFileLog)
            {
                lock (typeof(Log))
                {
                    if (ID > _iProgressHigh)
                    {
                        _iProgressHigh = ID;
                        for (int ndx = 0; ndx < (ID - _iProgressHigh + 1); ndx++)
                        {
                            Console.WriteLine(string.Empty.PadLeft(_iPadSize));
                        }
                    }
                    int CursorTop = Console.CursorTop;
                    Console.SetCursorPosition(0, Console.CursorTop - ID);
                    Console.Write(msg.PadRight(_iPadSize));
                    Console.SetCursorPosition(0, CursorTop);
                }
            }
        }

        public static string GetQuantityString(ulong quantity)
        {
            if (quantity < 1000)
                return quantity.ToString();
            else if (quantity < 1000 * 1000)
                return ((double)quantity / 1000).ToString("F1") + "K";
            else if (quantity < 1000 * 1000 * 1000)
                return ((double)quantity / (1000 * 1000)).ToString("F1") + "M";
            else
                return ((double)quantity / (1000 * 1000 * 1000)).ToString("F1") + "G";
        }

        public static string GetSizeString(ulong size)
        {
            if (size < 1024)
                return size.ToString() + " bytes";
            else if (size < 1024 * 1024)
                return (size / 1024).ToString() + " KB";
            else if (size < 1024 * 1024 * 1024)
                return (size / (1024 * 1024)).ToString() + " MB";
            else
                return ((double)size / (1024 * 1024 * 1024)).ToString("F1") + " GB";
        }
    }

	#region Packets
	public class IPv4Packet
	{
		public IPv4Packet(byte[] data, int offset)
		{
			Offset = offset;

			_versionAndLength = data[Offset++];
			TypeOfService = data[Offset++];
			TotalLength = (ushort)(data[Offset++] << 8);
			TotalLength += data[Offset++];
			Identification = (ushort)(data[Offset++] << 8);
			Identification += data[Offset++];
			FragmentFlags = (ushort)(data[Offset++] << 8);
			FragmentFlags += data[Offset++];
			TimeToLive = data[Offset++];
			_protocol = data[Offset++];
			HeaderCheckSum = (ushort)(data[Offset++] << 8);
			HeaderCheckSum += data[Offset++];
            OffsetAddress = Offset;
			SourceAddress = data[Offset++];
			SourceAddress += (uint)(data[Offset++] << 8);
			SourceAddress += (uint)(data[Offset++] << 16);
			SourceAddress += (uint)(data[Offset++] << 24);
			DestinationAddress = data[Offset++];
			DestinationAddress += (uint)(data[Offset++] << 8);
			DestinationAddress += (uint)(data[Offset++] << 16);
			DestinationAddress += (uint)(data[Offset++] << 24);
			int optionsLength = this.HeaderLength - FixedHeaderLength;
            Options = new ArraySegment<byte>(data, Offset, optionsLength);
            Offset += optionsLength;
		}

		protected int Offset;
        protected int OffsetAddress;
		public const int FixedHeaderLength = 20;
		public const int RouterAlertOptionLength = 4;

		private byte _versionAndLength;
		public int Version { get { return _versionAndLength >> 4; } }
		public int HeaderLength { get { return (_versionAndLength & 0xF) << 2; } }
		public byte TypeOfService;
		public ushort TotalLength;
		public ushort Identification;
		public ushort FragmentFlags;
		public byte TimeToLive;
		private byte _protocol;
		public ProtocolType ProtocolType { get { return (ProtocolType)_protocol; } }
		public ushort HeaderCheckSum;
		public uint SourceAddress;
		public uint DestinationAddress;
		public ArraySegment<byte> Options;

        public void SetAddresses(IPAddress addrSrc, IPAddress addrDst)
        {
            byte[] data = Options.Array;
            int ndxAddr = OffsetAddress;

            byte[] byteAddr = addrSrc.GetAddressBytes();
            data[ndxAddr++] = byteAddr[0];
            data[ndxAddr++] = byteAddr[1];
            data[ndxAddr++] = byteAddr[2];
            data[ndxAddr++] = byteAddr[3];

            byteAddr = addrDst.GetAddressBytes();
            data[ndxAddr++] = byteAddr[0];
            data[ndxAddr++] = byteAddr[1];
            data[ndxAddr++] = byteAddr[2];
            data[ndxAddr++] = byteAddr[3];
        }
	}

	public class IgmpPacket : IPv4Packet
	{
		public IgmpPacket(byte[] data, int offset) : base(data, offset)
		{
			if(base.ProtocolType != ProtocolType.Igmp)
				throw new ArgumentOutOfRangeException("data", "Invalid IGMP packet.");

            Type = data[Offset++];
            Code = data[Offset++];
			IgmpCheckSum = (ushort)(data[Offset++] << 8);
			IgmpCheckSum += data[Offset++];
		}

        public int IgmpVersion { get { return Type; } }
        public int IgmpCode { get { return Code; } }

        public byte Type;
        public byte Code;
		public ushort IgmpCheckSum;
	}

    public class IgmpV3Packet : IgmpPacket
    {
        public IgmpV3Packet(byte[] data, int offset)
            : base(data, offset)
		{
            switch (IgmpVersion)
            {
                case 0x11:
                    TypeName = "Membership query";
                    VersionName = ((Offset + 4) < TotalLength) ? "v3" : ((0 == IgmpCode) ? "v1" : "v2");
                    goto case 0x12;
                case 0x12:
                    if (0 == TypeName.Length)
                    {
                        TypeName = "Membership report";
                        VersionName = "v1";
                    }
                    goto case 0x16;
                case 0x16:
                    if (0 == TypeName.Length)
                    {
                        TypeName = "Membership report";
                        VersionName = "v2";
                    }
                    goto case 0x17;
                case 0x17:
                    if (0 == TypeName.Length)
                    {
                        TypeName = "Leave group"; ;
                        VersionName = "v2";
                    }
                    GroupAddress = data[Offset++];
                    GroupAddress += (uint)(data[Offset++] << 8);
                    GroupAddress += (uint)(data[Offset++] << 16);
                    GroupAddress += (uint)(data[Offset++] << 24);
                    break;
                case 0x22:
                    TypeName = "Membership report";
                    VersionName = "v3";

                    Offset++;
                    Offset++;
                    ushort nGroup = data[Offset++];
                    nGroup += (ushort)(data[Offset++] << 8);
                    if (nGroup > 0)
                    {
                        Offset += 4;
                        GroupAddress = data[Offset++];
                        GroupAddress += (uint)(data[Offset++] << 8);
                        GroupAddress += (uint)(data[Offset++] << 16);
                        GroupAddress += (uint)(data[Offset++] << 24);
                    }

                    break;

                default:
                    break;
            }

		}

        public string VersionName = string.Empty;
        public string TypeName=string.Empty;
        public uint GroupAddress;

    }

	public class UdpPacket : IPv4Packet
	{
		public UdpPacket(byte[] data, int offset) : base(data, offset)
		{
            if (ProtocolType.Udp == ProtocolType)
            {
                OffsetPort = Offset;
                SourcePort = (ushort)(data[Offset++] << 8);
                SourcePort += data[Offset++];
                DestinationPort = (ushort)(data[Offset++] << 8);
                DestinationPort += data[Offset++];
                UdpTotalLength = (ushort)(data[Offset++] << 8);
                UdpTotalLength += data[Offset++];
                UdpCheckSum = (ushort)(data[Offset++] << 8);
                UdpCheckSum += data[Offset++];
                UdpPayloadData = new ArraySegment<byte>(data, Offset, UdpTotalLength - UdpHeaderLength);
                Offset += UdpPayloadData.Count;
            }
		}

        protected int OffsetPort;
        public const ushort UdpHeaderLength = 8;
		public ushort SourcePort;
		public ushort DestinationPort;
		public ushort UdpTotalLength;
		public ushort UdpCheckSum;
		public ArraySegment<byte> UdpPayloadData;

        public void SetPorts(ushort PortSrc, ushort PortDst)
        {
            int ndxPort = OffsetPort;
            byte[] data = UdpPayloadData.Array;

            data[ndxPort++] = (byte)(PortSrc >> 8);
            data[ndxPort++] = (byte)(PortSrc & 0xFF);

            data[ndxPort++] = (byte)(PortDst >> 8);
            data[ndxPort++] = (byte)(PortDst & 0xFF);
        }
	}
	#endregion Packets

	internal static class WSAHelper
	{
		public static void EnableIgmpMulticast(Socket socket)
		{
			byte[] optionBytes = new byte[] { 1, 0, 0, 0 };
			byte[] result = new byte[4];
			socket.IOControl(IOControlCode.ReceiveAllIgmpMulticast, optionBytes, result);
		}

		public static void EnableAllMulticast(Socket socket)
		{
			byte[] optionBytes = new byte[] { 1, 0, 0, 0 };
			byte[] result = new byte[4];
			socket.IOControl(IOControlCode.ReceiveAllMulticast, optionBytes, result);
            //socket.IOControl(IOControlCode.ReceiveAll, optionBytes, result);
		}
	}

    internal class IPAddressComparer : Comparer<IPAddress>
    {
        public override int Compare(IPAddress x, IPAddress y)
        {
            int retVal = 0;
            byte[] bytesX = x.GetAddressBytes();
            byte[] bytesY = y.GetAddressBytes();

            for (int i = 0; (i < bytesX.Length) && (i < bytesY.Length); i++)
            {
                retVal = bytesX[i].CompareTo(bytesY[i]);
                if (0 != retVal)
                {
                    break;
                }
            }

            return retVal;
        }
    }

    public interface IIGMPReportInfo
    {
        bool IsServiceMode
        {
            get;
        }

        Action<IPAddress> NewHostCallback
        {
            get;
            set;
        }

        Action<IPAddress> DeleteHostCallback
        {
            get;
            set;
        }

        IPAddress[] McastToUnicast(IPAddress mcastAddr);

        bool IsExistHostMember(IPAddress hostAddress, IPAddress groupAddress);

        void StartIGMPProxy();
    }

    public class IgmpProxy : IIGMPReportInfo
    {
        private class MembershipItem : SortedList<IPAddress, DateTime>
        {
            private IPAddress _groupAddress;

            public MembershipItem(IPAddress grpAddr, IPAddress unicastAddr): base(new IPAddressComparer())
            {
                _groupAddress = grpAddr;
                this[unicastAddr] = DateTime.UtcNow;
            }

            public IPAddress GroupAddress
            {
                get
                {
                    return _groupAddress;
                }
            }

            public IPAddress[] UnicastMembers
            {
                get
                {
                    int ndx = 0;
                    IPAddress[] members = new IPAddress[this.Count];

                    IList<IPAddress> lstMembers = this.Keys;
                    foreach (IPAddress addr in lstMembers)
                    {
                        members[ndx++] = addr;
                    }
                    //Array.Resize(ref members, ndx);

                    return members;
                }
            }
        };

        private class MembershipCollection : KeyedCollection<IPAddress, MembershipItem>
        {
            // The parameterless constructor of the base class creates a 
            // KeyedCollection with an internal dictionary. For this code 
            // example, no other constructors are exposed.
            //
            public MembershipCollection() : base(null, 0) { }

            public object SyncRoot
            {
                get
                {
                    return ((ICollection)this).SyncRoot;
                }
            }

            public bool TryGetValue(IPAddress key, out MembershipItem value)
            {
                IDictionary<IPAddress, MembershipItem> thisDictionary = base.Dictionary;

                bool bIsFound = false;
                if (null != thisDictionary)
                {
                    bIsFound = thisDictionary.TryGetValue(key, out value);
                }
                else
                {
                    value = null;
                }

                return bIsFound;
            }
            // This is the only method that absolutely must be overridden,
            // because without it the KeyedCollection cannot extract the
            // keys from the items. The input parameter type is the 
            // second generic type argument, in this case OrderItem, and 
            // the return value type is the first generic type argument,
            // in this case int.
            //
            protected override IPAddress GetKeyForItem(MembershipItem item)
            {
                // In this example, the key is the part number.
                return item.GroupAddress;
            }
        }

        private const int MaxIgmpPacketSize = 256;
        private byte[] _bufferExt = new byte[MaxIgmpPacketSize];
        private byte[] _bufferInt = new byte[MaxIgmpPacketSize];
        private bool _bIsService = false;
        private IPAddress _remoteAddress;
        private IPAddress _localAddress;
        private IPAddress _AddressMCMin;
        private IPAddress _AddressMCMax;
        private IPAddress _hostRedirectFrom;
        private IPAddress _hostRedirectTo;
        private Socket _extSocket;
        private Socket _intSocket;
        private DateTime _lastHostQuery;
        private Queue<string> _QueueMessageLog = new Queue<string>();
        private IPAddressComparer _IPAddressCmp = new IPAddressComparer();
        private SortedDictionary<IPAddress, IPAddress> _hosts = new SortedDictionary<IPAddress, IPAddress>(new IPAddressComparer());
        private MembershipCollection _groups = new MembershipCollection();
        private Action<IPAddress> _NewHostCallback = delegate(IPAddress addr) {};
        private Action<IPAddress> _DeleteHostCallback= delegate(IPAddress addr) {};

        public bool IsServiceMode
        {
            get
            {
                return _bIsService;
            }
        }

        public Action<IPAddress> NewHostCallback
        {
            get
            {
                return _NewHostCallback;
            }

            set
            {
                _NewHostCallback = value;
            }
        }

        public Action<IPAddress> DeleteHostCallback
        {
            get
            {
                return _DeleteHostCallback;
            }

            set
            {
                _DeleteHostCallback = value;
            }
        }

        public IgmpProxy(IPAddress remoteAddress, IPAddress localAddress, bool IsService)
        {
            _remoteAddress = remoteAddress;
            _localAddress = localAddress;
            _bIsService = IsService;

            _extSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Igmp);
            _extSocket.MulticastLoopback = false;
            _extSocket.Bind(new IPEndPoint(remoteAddress, 0));
            WSAHelper.EnableIgmpMulticast(_extSocket);

            _intSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Igmp);
            _intSocket.MulticastLoopback = false;
            _intSocket.Bind(new IPEndPoint(localAddress, 0));
            WSAHelper.EnableIgmpMulticast(_intSocket);

            _AddressMCMin = IPAddress.Any;
            _AddressMCMax = IPAddress.Broadcast;

            string strAppParam;
            if (null != (strAppParam = ConfigurationManager.AppSettings["MulticastAddressScope"]))
            {
                int ndx = strAppParam.IndexOf('-');
                if (ndx < 0)
                {
                    _AddressMCMin = (0 == strAppParam.Length) ? IPAddress.Any : IPAddress.Parse(strAppParam);
                }
                else
                {
                    _AddressMCMin = IPAddress.Parse(strAppParam.Substring(0, ndx));
                    _AddressMCMax = IPAddress.Parse(strAppParam.Substring(ndx + 1));
                }
            }

            _hostRedirectFrom = IPAddress.Any;
            _hostRedirectTo = IPAddress.Any;

            if (null != (strAppParam = ConfigurationManager.AppSettings["HostRedirection"]))
            {
                int ndx = strAppParam.IndexOf('=');
                if (ndx < 0)
                {
                    _hostRedirectFrom = (0 == strAppParam.Length) ? IPAddress.Any : IPAddress.Parse(strAppParam);
                }
                else
                {
                    _hostRedirectFrom = IPAddress.Parse(strAppParam.Substring(0, ndx));
                    _hostRedirectTo = IPAddress.Parse(strAppParam.Substring(ndx + 1));
                }
            }
        }

        public IPAddress[] McastToUnicast(IPAddress mcastAddr)
        {
            IPAddress[] members = new IPAddress[0];

            try
            {
                lock (_groups.SyncRoot)
                {
                    members = _groups[mcastAddr].UnicastMembers;
                }
            }
            catch (KeyNotFoundException)
            {
            }

            return members;
        }

        public bool IsExistHostMember(IPAddress hostAddress, IPAddress groupAddress)
        {
            bool bExists = false;

            lock (((ICollection)_hosts).SyncRoot)
            {
                IPAddress addr;
                bExists = (_hosts.TryGetValue(hostAddress, out addr) && groupAddress.Equals(addr));
            }

            return bExists;
        }

        public void StartIGMPProxy()
        {
            BeginReceive();
        }

        private IPAddress GetInAddress(IAsyncResult asyncResult)
        {
            IPAddress address = (_bufferExt == (byte[])asyncResult.AsyncState) ? _remoteAddress : _localAddress;
            return address;
        }

        private Socket GetInSocket(IAsyncResult asyncResult)
        {
            Socket socket = (_bufferExt == (byte[])asyncResult.AsyncState) ? _extSocket : _intSocket;
            return socket;
        }

        private Socket GetOutSocket(IAsyncResult asyncResult)
        {
            Socket socket = (_bufferExt == (byte[])asyncResult.AsyncState) ? _intSocket : _extSocket;
            return socket;
        }

        private void BeginReceive()
        {
            _extSocket.BeginReceive(_bufferExt, 0, _bufferExt.Length, SocketFlags.None, OnReceive, _bufferExt);
            _intSocket.BeginReceive(_bufferInt, 0, _bufferInt.Length, SocketFlags.None, OnReceive, _bufferInt);
        }

        private void BeginInReceive(IAsyncResult asyncResult)
        {
            Socket inSocket = GetInSocket(asyncResult);

            byte[] buffer = (byte[])asyncResult.AsyncState;
            inSocket.BeginReceive(buffer, 0, buffer.Length, SocketFlags.None, OnReceive, buffer);
        }

        private void OnReceive(IAsyncResult asyncResult)
        {
            Socket inSocket = GetInSocket(asyncResult);
            Socket outSocket = GetOutSocket(asyncResult);

            int read = inSocket.EndReceive(asyncResult);
            byte[] buffer = (byte[])asyncResult.AsyncState;

            IgmpV3Packet packet = new IgmpV3Packet(buffer, 0);
            IPAddress inAddress = GetInAddress(asyncResult);
            IPAddress sourceAddress = new IPAddress(packet.SourceAddress);
            IPAddress destinationAddress = new IPAddress(packet.DestinationAddress);
            IPAddress groupAddress = new IPAddress(packet.GroupAddress);

            bool bSkip = false;

            if (sourceAddress.Equals(_hostRedirectFrom))
            {
                sourceAddress = _hostRedirectTo;
            }

            if (!inAddress.Equals(sourceAddress))
            {
                if (
                    _IPAddressCmp.Compare(groupAddress, _AddressMCMin) >= 0
                    && _IPAddressCmp.Compare(groupAddress, _AddressMCMax) <= 0
                    )
                {
                    switch (packet.IgmpVersion)
                    {
                        case 0x11:
                            if (inAddress.Equals(_remoteAddress))
                            {
                                OnHostQuery(groupAddress);
                            }
                            break;
                        case 0x12:
                            goto case 0x16;
                        case 0x16:
                            if (inAddress.Equals(_localAddress))
                            {
                                OnHostReport(sourceAddress, groupAddress);
                            }
                            break;
                        case 0x17:
                            goto case 0x22;
                        case 0x22:
                            if (inAddress.Equals(_localAddress))
                            {
                                bSkip = !OnGroupLeave(sourceAddress, groupAddress);
                            }
                            break;

                        default:
                            break;
                    }
                }
                else if (
                    0 == packet.GroupAddress
                    && 0x11 == packet.IgmpVersion
                    && inAddress.Equals(_remoteAddress)
                    )
                {
                    OnHostQuery(groupAddress);
                }
            }
            else
            {
                bSkip = true;
            }

            if (bSkip)
            {
                BeginInReceive(asyncResult);
            }
            else
            {
                outSocket.BeginSendTo(buffer, packet.HeaderLength, read - packet.HeaderLength, SocketFlags.None,
                    new IPEndPoint(destinationAddress, 0), OnSendTo, buffer);
            }
        }

        private void OnSendTo(IAsyncResult asyncResult)
        {
            Socket outSocket = GetOutSocket(asyncResult);

            int send = outSocket.EndSendTo(asyncResult);
            byte[] buffer = (byte[])asyncResult.AsyncState;

            if (send > 0)
            {
                IgmpV3Packet packet = new IgmpV3Packet(buffer, 0);
                IPAddress sourceAddress = new IPAddress(packet.SourceAddress);
                IPAddress destinationAddress = new IPAddress(packet.DestinationAddress);
                IPAddress groupAddress = new IPAddress(packet.GroupAddress);

                string strDirection = "-->";
                if (_intSocket != outSocket)
                {
                    strDirection = "<--";
                    IPAddress tmpAddr = sourceAddress;
                    sourceAddress = destinationAddress;
                    destinationAddress = tmpAddr;
                }

                string message = string.Format(
                    "{0} {1}{2}{3}[{4} {5}]",
                    packet.VersionName,
                    sourceAddress.ToString().PadRight(15),
                    strDirection,
                    destinationAddress.ToString().PadRight(15),
                    packet.TypeName.PadRight(17),
                    groupAddress.ToString()
                    );

                int iCount = 0;
                lock (((ICollection)_QueueMessageLog).SyncRoot)
                {
                    _QueueMessageLog.Enqueue(message);
                    iCount = _QueueMessageLog.Count;
                }

                if (IsServiceMode && iCount > 3)
                {
                    WriteLogMessage();
                }

                BeginInReceive(asyncResult);
            }
        }

        private void OnHostQuery(IPAddress group)
        {
            ArrayList hostsToDelete = new ArrayList();

            if (group.Equals(IPAddress.Any))
            {
                if (_lastHostQuery > DateTime.MinValue)
                {
                    lock (((ICollection)_hosts).SyncRoot)
                    {
                        lock (_groups.SyncRoot)
                        {
                            ArrayList groupsToDelete = new ArrayList();
                            foreach (MembershipItem memberitem in _groups)
                            {
                                ArrayList ToDelete = new ArrayList();
                                foreach (KeyValuePair<IPAddress, DateTime> pos in memberitem)
                                {
                                    if (pos.Value < _lastHostQuery)
                                    {
                                        ToDelete.Add(pos.Key);
                                    }
                                }

                                foreach (IPAddress pos in ToDelete)
                                {
                                    memberitem.Remove(pos);
                                }

                                if (0 == memberitem.Count)
                                {
                                    groupsToDelete.Add(memberitem.GroupAddress);
                                }

                                hostsToDelete.AddRange(ToDelete);
                            }

                            foreach (IPAddress pos in groupsToDelete)
                            {
                                _groups.Remove(pos);
                            }
                        }

                        foreach (IPAddress host in hostsToDelete)
                        {
                            _hosts.Remove(host);
                            this.DeleteHostCallback(host);
                        }
                    }
                }

                _lastHostQuery = DateTime.UtcNow;
            }
            else if (_lastHostQuery > DateTime.MinValue)
            {
                lock (((ICollection)_hosts).SyncRoot)
                {
                    lock (_groups.SyncRoot)
                    {
                        MembershipItem memberitem;
                        if (_groups.TryGetValue(group, out memberitem))
                        {
                            ArrayList ToDelete = new ArrayList();
                            foreach (KeyValuePair<IPAddress, DateTime> pos in memberitem)
                            {
                                if (pos.Value < _lastHostQuery)
                                {
                                    ToDelete.Add(pos.Key);
                                }
                            }

                            foreach (IPAddress host in ToDelete)
                            {
                                memberitem.Remove(host);
                            }

                            if (0 == memberitem.Count)
                            {
                                _groups.Remove(memberitem);
                            }

                            hostsToDelete.AddRange(ToDelete);
                        }
                    }

                    foreach (IPAddress host in hostsToDelete)
                    {
                        _hosts.Remove(host);
                        this.DeleteHostCallback(host);
                    }
                }
            }
        }

        private void OnHostReport(IPAddress host, IPAddress group)
        {
            bool bNewHost = false;

            lock (((ICollection)_hosts).SyncRoot)
            {
                bool bDoUpdate = false;
                IPAddress addr;

                bNewHost = !_hosts.TryGetValue(host, out addr);

                if(!bNewHost)
                {
                    bDoUpdate = !group.Equals(addr);
                }

                lock (_groups.SyncRoot)
                {
                    MembershipItem memberitem;
                    if (bDoUpdate)
                    {
                        memberitem = _groups[addr];
                        if (memberitem.Remove(host) && 0 == memberitem.Count)
                        {
                            _groups.Remove(memberitem);
                        }
                    }

                    if (_groups.TryGetValue(group, out memberitem))
                    {
                        IPAddress[] hosts = new IPAddress[memberitem.Count];
                        memberitem.Keys.CopyTo(hosts, 0);
                        DateTime now = DateTime.UtcNow;
                        foreach (IPAddress pos in hosts)
                        {
                            memberitem[pos] = now;
                        }

                        if (!memberitem.ContainsKey(host))
                        {
                            memberitem.Add(host, now);
                        }
                    }
                    else
                    {
                        memberitem = new MembershipItem(group, host);
                        _groups.Add(memberitem);
                    }
                }

                if (bNewHost || bDoUpdate)
                {
                    _hosts[host] = group;
                }

                if (bNewHost)
                {
                    this.NewHostCallback(host);
                }
            }
        }

        private bool OnGroupLeave(IPAddress host, IPAddress group)
        {
            bool bIsLastHost = true;

            lock (((ICollection)_hosts).SyncRoot)
            {
                IPAddress addr;
                if (_hosts.TryGetValue(host, out addr) && group.Equals(addr))
                {
                    lock (_groups.SyncRoot)
                    {
                        MembershipItem mitem = _groups[addr];
                        if (mitem.Remove(host))
                        {
                            if (0 == mitem.Count)
                            {
                                _groups.Remove(mitem);
                            }
                            else
                            {
                                bIsLastHost = false;
                            }
                        }

                        if (_groups.TryGetValue(IPAddress.None, out mitem))
                        {
                            mitem[host] = DateTime.UtcNow;
                        }
                        else
                        {
                            _groups.Add(new MembershipItem(IPAddress.None, host));
                        }
                    }

                    _hosts[host] = IPAddress.None;
                }
            }

            return bIsLastHost;
        }

        public void Close()
        {
            //_extSocket.Shutdown(SocketShutdown.Both);
            _extSocket.Close();
            //_intSocket.Shutdown(SocketShutdown.Both);
            _intSocket.Close();
        }

        public void WriteLogMessage()
        {
            while(_QueueMessageLog.Count > 0)
            {
                lock (((ICollection)_QueueMessageLog).SyncRoot)
                {
                    Log.Debug(_QueueMessageLog.Dequeue());
                }
            }
        }

        private string BytesToString(byte[] bytes, int offset, int length)
        {
            StringBuilder sb = new StringBuilder();
            for(int i = 0; i < length; i++)
            {
                byte b = bytes[offset + i];
                //if(i != 0)
                //    sb.Append(' ');
                sb.Append(b.ToString("X").PadLeft(2, '0'));
            }
            return sb.ToString();
        }
    }

    public class UdpBuffer : ICloneable
    {
        public const int BUFFER_SIZE = 2048;
        public byte[] buffer = new byte[BUFFER_SIZE];

        public void CopyFrom(UdpBuffer ub)
        {
            ub.buffer.CopyTo(buffer, 0);
        }

        public Object Clone()
        {
            UdpBuffer clone = (UdpBuffer)this.MemberwiseClone();

            clone.buffer = (byte[])this.buffer.Clone();

            return clone;
        }
    }

    public class UnicastSender
    {
        //private const uint PACKETS_SIZE = 16;
        //private const uint OVERFLOW_SIZE = 10;
        //private const uint UNDERFLOW_SIZE = 5;
        //private const uint ENDBUFF_SIZE = 1;

        private const uint PACKETS_SIZE = 64;
        private const uint OVERFLOW_SIZE = 40;
        private const uint UNDERFLOW_SIZE = 20;
        private const uint ENDBUFF_SIZE = 2;

        private IIGMPReportInfo _reportInfo;
        private IPAddress _internalAddress;
        private IPAddress _unicastAddress;
        private IPAddress _currChanAddress = IPAddress.None;
        private UdpBuffer[] _soPackets = new UdpBuffer[PACKETS_SIZE];
        private Socket _outSocket;
        private int _iPlusPort;
        private int _iDestinationPort;
        private int _inSendOp = 2;
        private uint _deltaBuff;
        private uint _sentPackets;
        private uint _sentChanPackets;
        private ulong _sentBytes;
        private ulong _lastSentBytes;
        private bool _bReceiveReady = true;
        private DateTime _lastUpdate = DateTime.UtcNow;
        private string _strMessageLog = string.Empty;
        private string _strLastMessageLog = string.Empty;
        private Action<IPAddress> _BeginReceive;

        static UnicastSender()
        {
            PrintConfiguration();
        }

        private static void PrintConfiguration()
        {
            Console.WriteLine("Buffer configuration:");
            Console.WriteLine("---------------------");
            Console.WriteLine("Packets buffer size: {0}", PACKETS_SIZE);
            Console.WriteLine("Overflowing state level: {0}", OVERFLOW_SIZE);
            Console.WriteLine("Underflowing state level: {0}", UNDERFLOW_SIZE);

            Console.WriteLine();
        }

        public UnicastSender(
            IIGMPReportInfo reportInfo,
            IPAddress internalAddress,
            IPAddress unicastAddress,
            int iPlusPort,
            int iDstPort,
            Action<IPAddress> BeginReceive)
        {
            _reportInfo = reportInfo;

            _internalAddress = internalAddress;
            _unicastAddress = unicastAddress;

            _iPlusPort = iPlusPort;
            _iDestinationPort = iDstPort;
            _BeginReceive = BeginReceive;

            _outSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            _outSocket.Bind(new IPEndPoint(_internalAddress, 0));
            //_outSocket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.HeaderIncluded, true);
        }

        public IPAddress UnicastAddress
        {
            get
            {
                return _unicastAddress;
            }

            set
            {
                _unicastAddress = value;
            }
        }

        public bool ReceiveReady
        {
            get
            {
                return _bReceiveReady;
            }
        }

        private void BeginSendTo()
        {
            uint delta;
            UdpBuffer ub;

            lock (_soPackets.SyncRoot)
            {
                delta = _deltaBuff;
                ub = _soPackets[_sentPackets % PACKETS_SIZE];
            }

            if (delta > 0)
            {
                UdpPacket packet = new UdpPacket(ub.buffer, 0);
                IPAddress destAddress = new IPAddress(packet.DestinationAddress);
                IPAddress hostAddress = _unicastAddress;

                int iDestPort = (0 == _iPlusPort) ? ((0 == _iDestinationPort) ? packet.DestinationPort : _iDestinationPort) :
                    ((byte)(packet.DestinationAddress >> 24) + _iPlusPort);

                if (_reportInfo.IsExistHostMember(hostAddress, destAddress))
                {
                    _outSocket.BeginSendTo(packet.UdpPayloadData.Array, packet.UdpPayloadData.Offset, packet.UdpPayloadData.Count,
                        SocketFlags.None, new IPEndPoint(hostAddress, iDestPort), OnSendTo, ub);
                }
                else
                {
                    lock (_soPackets.SyncRoot)
                    {
                        _sentPackets += delta;
                        _deltaBuff -= delta;
                        delta = _deltaBuff;
                    }
                    Interlocked.Increment(ref _inSendOp);
                }


                //UdpPacket packet = new UdpPacket(ub.buffer, 0);
                //int iDestinPort = (0 == _iDestinationPort) ? packet.DestinationPort : _iDestinationPort;                
                //IPEndPoint ip = (IPEndPoint)_outSocket.LocalEndPoint;
                //packet.SetAddresses(ip.Address, _destinationAddress);
                //packet.SetPorts((ushort)ip.Port, (ushort)iDestinPort);
                //_outSocket.BeginSendTo(ub.buffer, 0, packet.TotalLength,
                //SocketFlags.None, new IPEndPoint(_destinationAddress, iDestinPort), OnSendTo, ub);
            }
            else
            {
                Interlocked.Increment(ref _inSendOp);
            }

            if (delta <= UNDERFLOW_SIZE)
            {
                _bReceiveReady = true;
                _BeginReceive(this.UnicastAddress);
            }
        }

        public UdpBuffer OnReceive(UdpBuffer ub)
        {
            UdpPacket packet = new UdpPacket(ub.buffer, 0);
            UdpBuffer ubNext;
            uint delta;

            lock (_soPackets.SyncRoot)
            {
                ulong ndx = (_sentPackets + _deltaBuff) % PACKETS_SIZE;
                ubNext = _soPackets[ndx];
                _soPackets[ndx] = ub;

                _deltaBuff++;
                delta = _deltaBuff;
            }

            IPAddress destAddress = new IPAddress(packet.DestinationAddress);
            bool bSwitch = false;
            if (!destAddress.Equals(_currChanAddress))
            {
                lock (_soPackets.SyncRoot)
                {
                    _sentChanPackets = 0;
                    _sentBytes = 0;
                    _lastSentBytes = 0;
                }
                bSwitch = true;
                _currChanAddress = destAddress;
            }

            if (bSwitch)
            {
                Log.Message(string.Format("Host {0} is switched to multicast address {1}", this.UnicastAddress, destAddress));
            }

            if (delta >= (PACKETS_SIZE - ENDBUFF_SIZE))
            {
                _bReceiveReady = false;
            }

            if (null == ubNext)
            {
                ubNext = new UdpBuffer();
            }

            if (delta >= OVERFLOW_SIZE)
            {
                if (Interlocked.Decrement(ref _inSendOp) > 0)
                {
                    BeginSendTo();
                }
                else
                {
                    Interlocked.Increment(ref _inSendOp);
                }
            }

            return ubNext;
        }

        private void OnSendTo(IAsyncResult asyncResult)
        {
            int sendCount = _outSocket.EndSendTo(asyncResult);

            if (sendCount > 0)
            {
                UdpBuffer ub = (UdpBuffer)asyncResult.AsyncState;

                _sentBytes += (ulong)sendCount;

                uint sentPackets;
                lock (_soPackets.SyncRoot)
                {
                    sentPackets = ++_sentChanPackets;
                    _sentPackets++;
                    _deltaBuff--;
                }

                DateTime timeNow = DateTime.UtcNow;
                if (_lastUpdate.AddSeconds(3) < timeNow)
                {
                    ulong mseconds = Math.Max(100, (ulong)(timeNow - _lastUpdate).TotalMilliseconds);
                    string message = string.Format(
                                            "<{0}>: Forwarded {1} packets ({2}) at {3:F1} Mbit/s buffer: {4}%",
                                            _currChanAddress.ToString(),
                                            Log.GetQuantityString(sentPackets),
                                            Log.GetSizeString(_sentBytes),
                                            ((double)(_sentBytes - _lastSentBytes) * 8) / (ulong)(mseconds * 1000),
                                            (_deltaBuff * 100) / PACKETS_SIZE
                                            );

                    _lastUpdate = timeNow;
                    _lastSentBytes = _sentBytes;
                    _strMessageLog = message;
                }

                BeginSendTo();
            }
        }

        public void Close()
        {
            //_outSocket.Shutdown(SocketShutdown.Both);
            _outSocket.Close();
        }

        public void WriteLogMessage(int ndx)
        {
            string message = _strMessageLog;
            if (message != _strLastMessageLog)
            {
                Log.MessageProgress(message, ndx);
                _strLastMessageLog = message;
            }
        }
    }

	public class MulticastProxy
	{
        private class SendersCollection : KeyedCollection<IPAddress, UnicastSender>
        {
            public SendersCollection() : base(null, 0)
            {
            }

            public object SyncRoot
            {
                get
                {
                    return ((ICollection)this).SyncRoot;
                }
            }

            public bool TryGetValue(IPAddress key, out UnicastSender value)
            {
                IDictionary<IPAddress, UnicastSender> thisDictionary = base.Dictionary;

                bool bIsFound = false;
                if(null != thisDictionary)
                {
                    bIsFound = thisDictionary.TryGetValue(key, out value);
                }
                else
                {
                    value = null;
                }

                return bIsFound;
            }

            protected override IPAddress GetKeyForItem(UnicastSender item)
            {
                return item.UnicastAddress;
            }
        }

        public const int UNICAST_SENDERS_MAX = 7;

        private IIGMPReportInfo _reportInfo;
        private IPAddress _externalAddress;
		private IPAddress _internalAddress;
		private Socket _inSocket;
        private Socket _fakeSocket;
        private int _iSourcePort;
        private int _iPlusPort;
        private int _iDestinationPort;
        private int _inReceiveOp=2;
        private uint _sendPackets;
        private uint _dropPackets;
        private Single _maxDropPart;
        private Single _currDropPart;
        private UdpBuffer _ubBuffer = new UdpBuffer();
        private SendersCollection _Senders = new SendersCollection();
        private string _strMessageLog = string.Empty;
        private string _strLastMessageLog = string.Empty;

        public MulticastProxy(
            IIGMPReportInfo reportInfo,
            IPAddress externalAddress,
            IPAddress internalAddress,
            int iSrcPort,
            int iPlusPort,
            int iDstPort)
		{
            _reportInfo = reportInfo;

			_externalAddress = externalAddress;
			_internalAddress = internalAddress;

            _iSourcePort = iSrcPort;
            _iPlusPort = iPlusPort;
            _iDestinationPort = iDstPort;

            _inSocket = new Socket(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.Udp);
			_inSocket.MulticastLoopback = false;
			_inSocket.Bind(new IPEndPoint(externalAddress, 0));
			WSAHelper.EnableAllMulticast(_inSocket);

            //IPAddress sourceAddress = IPAddress.Parse("235.10.10.82");
            //_inSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            //_inSocket.Bind(new IPEndPoint(externalAddress, MULTICAST_PORT));
            //_inSocket.SetSocketOption(
                //SocketOptionLevel.IP,
                //SocketOptionName.AddMembership,
                //new MulticastOption(sourceAddress, externalAddress));

            if (0 != _iSourcePort)
            {
                _fakeSocket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                _fakeSocket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);
                _fakeSocket.Bind(new IPEndPoint(externalAddress, _iSourcePort));
            }

            PrintConfiguration();

            _reportInfo.NewHostCallback = OnNewHostAddress;
            _reportInfo.DeleteHostCallback = OnDeleteHostAddress;
		}

        private void LogMessage(string strmsg)
        {
            if (_reportInfo.IsServiceMode)
            {
                Log.Message(strmsg);
            }
            else
            {
                _strMessageLog = strmsg;
            }
        }

        private void PrintConfiguration()
        {
            Console.WriteLine("Network configuration:");
            Console.WriteLine("----------------------");
            Console.WriteLine("External interface: {0}", _externalAddress.ToString());
            Console.WriteLine("Internal interface: {0}", _internalAddress.ToString());
            if (0 != _iDestinationPort)
            {
                Console.Write(":{0}", _iDestinationPort);
            }
            else if(0 != _iPlusPort)
            {
                Console.Write(":+{0}", _iPlusPort);
            }
            Console.WriteLine();
            if (0 != _iSourcePort)
            {
                Console.WriteLine("Multicast source port: {0}", _iSourcePort);
            }

            Console.WriteLine();
        }

        private void BeginReceive(IPAddress addr)
		{
            bool bTryReceive = false;

            lock (_Senders.SyncRoot)
            {
                bTryReceive = _Senders.Contains(addr);
            }

            if (bTryReceive)
            {
                if (Interlocked.Decrement(ref _inReceiveOp) > 0)
                {
                    _inSocket.BeginReceive(_ubBuffer.buffer, 0, _ubBuffer.buffer.Length, SocketFlags.None, OnReceive, _ubBuffer);
                }
                else
                {
                    Interlocked.Increment(ref _inReceiveOp);
                }
            }
		}

		private void OnReceive(IAsyncResult asyncResult)
		{
            int read = _inSocket.EndReceive(asyncResult);
			if(read > 0)
			{
                UdpBuffer ub = (UdpBuffer)asyncResult.AsyncState;
                UdpPacket packet = new UdpPacket(ub.buffer, 0);
                IPAddress destAddress = new IPAddress(packet.DestinationAddress);
                IPAddress srcAddress = new IPAddress(packet.SourceAddress);
                IPAddress[] uniAddresses = _reportInfo.McastToUnicast(destAddress);
                bool bReceiveReady = false;

                if (
                    !srcAddress.Equals(_externalAddress) &&
                    (0 == _iSourcePort || _iSourcePort == packet.DestinationPort) &&
                    uniAddresses.Length > 0
                   )
                {
                    UdpBuffer ubCurrent = ub;
                    UdpBuffer ubNext = ub;
                    foreach (IPAddress addr in uniAddresses)
                    {
                        lock (_Senders.SyncRoot)
                        {
                            UnicastSender sender;
                            if (_Senders.TryGetValue(addr, out sender))
                            {
                                if(sender.ReceiveReady)
                                {
                                    if (ubCurrent != ubNext)
                                    {
                                        ubNext.CopyFrom(ubCurrent);
                                        ubCurrent = ubNext;
                                    }

                                    ubNext = sender.OnReceive(ubCurrent);
                                    bReceiveReady |= sender.ReceiveReady;
                                    _sendPackets++;
                                }
                                else
                                {
                                    _dropPackets++;
                                    _currDropPart = (Single)_dropPackets/(Single)_sendPackets;
                                }
                            }
                        }
                    }

                    if (!bReceiveReady)
                    {
                        lock (_Senders.SyncRoot)
                        {
                            if (_Senders.Count > 0)
                            {
                                foreach (UnicastSender sender in _Senders)
                                {
                                    bReceiveReady |= sender.ReceiveReady;
                                }
                            }
                        }
                    }

                    _ubBuffer = ubNext;
                }
                else
                {
                    lock (_Senders.SyncRoot)
                    {
                        bReceiveReady = (_Senders.Count > 0);
                    }
                }

                if (bReceiveReady)
                {
                    _inSocket.BeginReceive(_ubBuffer.buffer, 0, _ubBuffer.buffer.Length, SocketFlags.None, OnReceive, _ubBuffer);
                }
                else
                {
                    Interlocked.Increment(ref _inReceiveOp);
                }
			}
		}

        private void OnNewHostAddress(IPAddress addr)
        {
            int count = 0;

            lock (_Senders.SyncRoot)
            {
                count = _Senders.Count;
                if (count < UNICAST_SENDERS_MAX)
                {
                    _Senders.Add(new UnicastSender(_reportInfo, _internalAddress, addr, _iPlusPort, _iDestinationPort, BeginReceive));
                    LogMessage(string.Format("Multicast forwarding to host {0} is started.", addr));
                }
            }

            if (0 == count)
            {
                _sendPackets = 0;
                _dropPackets = 0;
                _currDropPart = 0;
                _maxDropPart = 0;
                BeginReceive(addr);
            }
        }

        private void OnDeleteHostAddress(IPAddress addr)
        {
            int count = 0;

            lock (_Senders.SyncRoot)
            {
                if (_Senders.Remove(addr))
                {
                    LogMessage(string.Format("Multicast forwarding to host {0} is finished.", addr));
                }

                count = _Senders.Count;
            }

            if (0 == count)
            {
                string message =
                    string.Format("Total forwarded {0} packets, among them dropped {1} ({2:F2}%)",
                    Log.GetQuantityString(_sendPackets),
                    Log.GetQuantityString(_dropPackets),
                    100 * _currDropPart);

                LogMessage(message);
            }
        }

		public void Close()
		{
            lock (_Senders.SyncRoot)
            {
                foreach (UnicastSender sender in _Senders)
                {
                    sender.Close();
                }
            }

			//_inSocket.Shutdown(SocketShutdown.Both);
			_inSocket.Close();
		}

        public void WriteLogMessage()
        {
            UnicastSender[] senders;
            lock (_Senders.SyncRoot)
            {
                senders = new UnicastSender[_Senders.Count];
                for (int ndx = 0; ndx < _Senders.Count; ndx++)
                {
                    senders[ndx] = _Senders[ndx];
                }
            }

            for (int ndx = 0; ndx < senders.Length; ndx++)
            {
                senders[ndx].WriteLogMessage(ndx);
            }

            string message = _strMessageLog;
            if (message != _strLastMessageLog)
            {
                Log.Message(message);
                _strLastMessageLog = message;
            }

            if (_currDropPart > _maxDropPart)
            {
                _maxDropPart = _currDropPart;
                Log.Message(string.Format("Total forwarded {0} packets, among them dropped {1} ({2:F2}%)",
                    Log.GetQuantityString(_sendPackets), Log.GetQuantityString(_dropPackets), 100 * _currDropPart));
            }
        }
	}
}
