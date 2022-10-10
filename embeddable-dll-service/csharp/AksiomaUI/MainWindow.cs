/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

using System;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Windows.Forms;
using System.Threading;
using System.IO.Pipes;
using System.Diagnostics;
using System.Net.Sockets;
using System.Security.AccessControl;

namespace DemoUI
{
    public partial class MainWindow : Form
    {
        private static readonly string userDirectory = Path.Combine(Path.GetDirectoryName(Process.GetCurrentProcess().MainModule.FileName), ""); //TODO: put in Program Files in real code.
        private static string configFileUFA = "";
        private static string configFileRT = "";
        private static string configFile = "";
        private static string open = "0";        
        private static readonly string logFile = Path.Combine(userDirectory, "log.bin");

        private Tunnel.Ringlogger log;
        private Thread logPrintingThread, transferUpdateThread;
        private volatile bool threadsRunning;
        private bool connected;

        public MainWindow()
        {
            makeConfigDirectory();
            InitializeComponent();
            Application.ApplicationExit += Application_ApplicationExit;
            try { File.Delete(logFile); } catch { }
            log = new Tunnel.Ringlogger(logFile, "GUI");
            logPrintingThread = new Thread(new ThreadStart(tailLog));
            transferUpdateThread = new Thread(new ThreadStart(tailTransfer));        
        }

        private void makeConfigDirectory()
        {
            var str1 = "_RT";
            var str2 = "_UFA";            
            string[] second = Directory.GetFiles(userDirectory);
            for (int i = 0; i < second.Length; i++)
            {
                System.Diagnostics.Debug.WriteLine(second[i]);
                if (second[i].Contains(str1)) { configFileRT = second[i]; }                               
                if (second[i].Contains(str2)) { configFileUFA = second[i]; }                
            }
            if (configFileUFA=="")
            {
                MessageBox.Show("Не помещен файл UFA.conf.\r\nВыход из программы!", "Предупреждение", MessageBoxButtons.OK,
                                MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                threadsRunning = false;
                logPrintingThread.Interrupt();
                transferUpdateThread.Interrupt();
                try { logPrintingThread.Join(); } catch { }
                try { transferUpdateThread.Join(); } catch { }
                Application.Exit();
            }
            if (configFileRT=="")
            {
                MessageBox.Show("Не помещен файл RT.conf.\r\nВыход из программы!", "Предупреждение", MessageBoxButtons.OK,
                                MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                threadsRunning = false;
                logPrintingThread.Interrupt();
                transferUpdateThread.Interrupt();
                try { logPrintingThread.Join(); } catch { }
                try { transferUpdateThread.Join(); } catch { }
                Application.Exit();
            }
        }
               

        private void tailLog()
        {
            var cursor = Tunnel.Ringlogger.CursorAll;
            var str1 = "because we stopped";
            var str2 = "did not complete";
            var str3 = "Shutting down";
            var str4 = "Служба не ответила на запрос";
            while (threadsRunning)
            {
                var lines = log.FollowFromCursor(ref cursor);
                foreach (var line in lines)
                {
                    if (line.Contains(str4)) 
                    {
                        MessageBox.Show("Выключите лишние службы.\r\nВыход из программы!", "Ошибка инциилизации службы Wireguard", MessageBoxButtons.OK,
                                    MessageBoxIcon.Hand, MessageBoxDefaultButton.Button1, MessageBoxOptions.DefaultDesktopOnly);
                        threadsRunning = false;
                        logPrintingThread.Interrupt();
                        transferUpdateThread.Interrupt();
                        try { logPrintingThread.Join(); } catch { }
                        try { transferUpdateThread.Join(); } catch { }
                        Application.Exit();
                    }

                    if (line.Contains(str1) || line.Contains(str2)) 
                    {
                        //threadsRunning = false;
                        Tunnel.Service.Remove(configFileUFA, true);
                        Tunnel.Service.Remove(configFileRT, true);
                        //System.Diagnostics.Debug.WriteLine(configFile);
                    }
                    if (line.Contains(str3))
                    {
                        if (configFile == configFileUFA) 
                        { 
                            configFile = configFileRT;
                            notifyIcon1.Text= "Аксиома VPN клиент. Канал Резервный";
                            Text = notifyIcon1.Text;
                        } 
                        else 
                        { 
                            configFile = configFileUFA; 
                            notifyIcon1.Text= "Аксиома VPN клиент. Канал Основной";
                            Text = notifyIcon1.Text;

                        }
                        Task.Run(() => Tunnel.Service.Add(configFile, true));
                        //threadsRunning = true;
                    }   
                    logBox.Invoke(new Action<string>(logBox.AppendText), new object[] { line + "\r\n" });
                }                
                try
                {
                    Thread.Sleep(300);
                }
                catch
                {
                    break;
                }
            }
        }

        private void tailTransfer()
        {
            Tunnel.Driver.Adapter adapter = null;
            while (threadsRunning)
            {
                if (adapter == null)
                {
                    while (threadsRunning)
                    {
                        System.Net.NetworkInformation.Ping ping = new System.Net.NetworkInformation.Ping();
                        System.Net.NetworkInformation.PingReply pingReply = ping.Send("10.8.0.1");
                        //System.Diagnostics.Debug.WriteLine(pingReply.RoundtripTime); 
                        //System.Diagnostics.Debug.WriteLine(pingReply.Status);        
                        //System.Diagnostics.Debug.WriteLine(pingReply.Address);       
                        try
                        {
                            adapter = Tunnel.Service.GetAdapter(configFile);
                            break;
                        }
                        catch
                        {
                            try
                            {
                                Thread.Sleep(1000);
                            }
                            catch { }
                        }
                    }
                }
                if (adapter == null)
                    continue;
                try
                {
                    ulong rx = 0, tx = 0;
                    var config = adapter.GetConfiguration();
                    foreach (var peer in config.Peers)
                    {
                        rx += peer.RxBytes;
                        tx += peer.TxBytes;
                    }
                    Invoke(new Action<ulong, ulong>(updateTransferTitle), new object[] { rx, tx });
                    Thread.Sleep(1000);
                }
                catch { adapter = null; }
            }
        }

        private void Application_ApplicationExit(object sender, EventArgs e)
        {
            Tunnel.Service.Remove(configFile, true);
            try { File.Delete(logFile); } catch { }            
        }

        private void MainWindow_Load(object sender, EventArgs e)
        {
            connectButton_Click(sender, e);            
            threadsRunning = true;
            logPrintingThread.Start();
            transferUpdateThread.Start();            
        }

        private void MainWindow_FormClosing(object sender, FormClosingEventArgs e)
        {
            if (e.CloseReason == CloseReason.UserClosing)
            {
                this.Hide();
                e.Cancel = true;
            }          

            
        }

        private static string formatBytes(ulong bytes)
        {
            decimal d = bytes;
            string selectedUnit = null;
            foreach (string unit in new string[] { "Байт", "КБ", "МБ", "ГБ", "ТБ" })
            {
                selectedUnit = unit;
                if (d < 1024)
                    break;
                d /= 1024;
            }
            return string.Format("{0:0.##} {1}", d, selectedUnit);
        }

        private void updateTransferTitle(ulong rx, ulong tx)
        {
            var titleBase = Text;
            var idx = titleBase.IndexOf(" - ");
            if (idx != -1)
                titleBase = titleBase.Substring(0, idx);
            if (rx == 0 && tx == 0)
            {
                //Text = titleBase;
                Text = string.Format("{0} - Входящий: {1}, Исходящий: {2}", titleBase, formatBytes(rx), formatBytes(tx));               
            }
            else
            {
                Text = string.Format("{0} - Входящий: {1}, Исходящий: {2}", titleBase, formatBytes(rx), formatBytes(tx));               
            }
        }

        
        private void MainWindow_Activated(object sender, EventArgs e)
        {
            if (open == "0")
            {
                System.Diagnostics.Debug.WriteLine("Open");
                this.Hide();
                this.Visible = false;
                open = "1";
            }
        }

        private void notifyIcon1_DoubleClick(object sender, EventArgs e)
        {
            if (this.Visible) { this.Visible = false; } else { this.Visible = true; }
        }

        private void toolStripMenuItem1_Click(object sender, EventArgs e)
        {
            this.Visible = true;
        }

        private void toolStripMenuItem2_Click(object sender, EventArgs e)
        {
            threadsRunning = false;
            logPrintingThread.Interrupt();
            transferUpdateThread.Interrupt();
            try { logPrintingThread.Join(); } catch { }
            try { transferUpdateThread.Join(); } catch { }
            Application.Exit();
        }

        private async void connectButton_Click(object sender, EventArgs e)
        {
            this.Hide();
            if (connected)
            {
                connectButton.Enabled = false;
                await Task.Run(() =>
                {
                    Tunnel.Service.Remove(configFile, true);                    
                });
                updateTransferTitle(0, 0);
                connectButton.Text = "&Подключиться";
                connectButton.Enabled = true;
                connected = false;
                return;
            }

            connectButton.Enabled = false;
            try
            {
                var configFile = configFileUFA;
                await Task.Run(() => Tunnel.Service.Add(configFile, true));
                connected = true;
                connectButton.Text = "&Отключиться";
            }
            catch (Exception ex)
            {
                log.Write(ex.Message);             
            }
            connectButton.Enabled = true;
        }
    }
}
