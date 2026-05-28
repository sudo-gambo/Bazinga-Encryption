using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;

namespace encryptionTool
{
    // ── History model ────────────────────────────────────────────────────────
    public class HistoryEntry
    {
        public string Id        { get; set; } = Guid.NewGuid().ToString();
        public string Type      { get; set; } = "";   // "Folder Encrypted" | "Folder Decrypted" | "File Encrypted" | "File Decrypted" | "Key Generated"
        public string Path      { get; set; } = "";
        public string Algorithm { get; set; } = "ChaCha20-Poly1305";
        public string Key       { get; set; } = "";
        public string Date      { get; set; } = "";
    }

    // ── Settings model ───────────────────────────────────────────────────────
    public class AppSettings
    {
        public bool IsDark { get; set; } = false;
    }

    public partial class MainWindow : Window
    {
        // ── DLL imports ──────────────────────────────────────────────────────
        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int encrypt_folder(string folder, StringBuilder keyOut, int bufLen);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int decrypt_folder(string folder, string base64Key);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int encrypt_file(string path, string base64Key);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int decrypt_file(string path, string base64Key);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int generate_key(StringBuilder keyOut, int bufLen);

        // ── State ────────────────────────────────────────────────────────────
        private bool _isDark = false;
        private string _lastKey = "";
        private List<HistoryEntry> _history = new();

        private static readonly string HistoryPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "BazingaVault", "history.json");

        private static readonly string SettingsPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "BazingaVault", "settings.json");

        public MainWindow()
        {
            InitializeComponent();
            LoadSettings();
            LoadHistory();
        }

        // ── Settings persistence ──────────────────────────────────────────────
        private void LoadSettings()
        {
            try
            {
                if (!File.Exists(SettingsPath)) return;
                var s = JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(SettingsPath));
                if (s == null) return;
                _isDark = s.IsDark;
                ApplyTheme(_isDark);
            }
            catch { }
        }

        private void SaveSettings()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(SettingsPath)!);
                File.WriteAllText(SettingsPath, JsonSerializer.Serialize(
                    new AppSettings { IsDark = _isDark },
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        // ── History persistence ───────────────────────────────────────────────
        private void LoadHistory()
        {
            try
            {
                if (!File.Exists(HistoryPath)) return;
                var json = File.ReadAllText(HistoryPath);
                _history = JsonSerializer.Deserialize<List<HistoryEntry>>(json) ?? new();
            }
            catch { _history = new(); }
            RefreshHistoryUI();
        }

        private void SaveHistory()
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(HistoryPath)!);
                File.WriteAllText(HistoryPath, JsonSerializer.Serialize(_history,
                    new JsonSerializerOptions { WriteIndented = true }));
            }
            catch { }
        }

        private void AddHistoryEntry(HistoryEntry entry)
        {
            _history.Insert(0, entry);
            SaveHistory();
            RefreshHistoryUI();
        }

        private void RefreshHistoryUI()
        {
            HistoryEmpty.Visibility = _history.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            HistoryList.Visibility  = _history.Count > 0  ? Visibility.Visible : Visibility.Collapsed;
            HistoryList.ItemsSource = null;
            HistoryList.ItemsSource = _history;
        }

        // ── Browse helpers ────────────────────────────────────────────────────
        private string? BrowseFolder(string title)
        {
            var dialog = new OpenFolderDialog
            {
                Title = title,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            return dialog.ShowDialog() == true ? dialog.FolderName : null;
        }

        private string? BrowseFile(string title)
        {
            var dialog = new OpenFileDialog
            {
                Title = title,
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            return dialog.ShowDialog() == true ? dialog.FileName : null;
        }

        // ── Browse (encrypt page) ─────────────────────────────────────────────
        private void BrowseEncryptFolder_Click(object sender, RoutedEventArgs e)
        {
            var path = BrowseFolder("Select Folder to Encrypt");
            if (path == null) return;
            EncryptPathInput.Text = path;
            EncryptStatus.Text = "FOLDER_READY";
        }

        private void BrowseEncryptFile_Click(object sender, RoutedEventArgs e)
        {
            var path = BrowseFile("Select File to Encrypt");
            if (path == null) return;
            EncryptPathInput.Text = path;
            EncryptStatus.Text = "FILE_READY";
        }

        // ── Browse (decrypt page) ─────────────────────────────────────────────
        private void BrowseDecryptFolder_Click(object sender, RoutedEventArgs e)
        {
            var path = BrowseFolder("Select Folder to Decrypt");
            if (path == null) return;
            DecryptPathInput.Text = path;
            DecryptStatus.Text = "FOLDER_READY";
        }

        private void BrowseDecryptFile_Click(object sender, RoutedEventArgs e)
        {
            var path = BrowseFile("Select File to Decrypt");
            if (path == null) return;
            DecryptPathInput.Text = path;
            DecryptStatus.Text = "FILE_READY";
        }

        // ── Encrypt ───────────────────────────────────────────────────────────
        private void LockButton_Click(object sender, RoutedEventArgs e)
        {
            string path = EncryptPathInput.Text.Trim();
            if (string.IsNullOrEmpty(path)) { EncryptStatus.Text = "NO_PATH"; return; }

            bool isFolder = Directory.Exists(path);
            bool isFile   = File.Exists(path);

            if (!isFolder && !isFile) { EncryptStatus.Text = "INVALID_PATH"; return; }

            EncryptStatus.Text = "ENCRYPTING...";
            LockButton.IsEnabled = false;

            try
            {
                string key;
                int result;

                if (isFolder)
                {
                    var keyBuf = new StringBuilder(512);
                    result = encrypt_folder(path, keyBuf, keyBuf.Capacity);
                    key = keyBuf.ToString();
                }
                else
                {
                    var keyBuf = new StringBuilder(512);
                    result = generate_key(keyBuf, keyBuf.Capacity);
                    if (result != 0) { EncryptStatus.Text = $"KEYGEN_ERR: {result}"; return; }
                    key = keyBuf.ToString();
                    result = encrypt_file(path, key);
                }

                if (result == 0)
                {
                    _lastKey = key;
                    KeyOutputBox.Text = _lastKey;
                    KeyOutputPanel.Visibility = Visibility.Visible;
                    EncryptStatus.Text = "SUCCESS — save your key!";

                    AddHistoryEntry(new HistoryEntry
                    {
                        Type = isFolder ? "Folder Encrypted" : "File Encrypted",
                        Path = path,
                        Key  = _lastKey,
                        Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                else { EncryptStatus.Text = $"ERR_CODE: {result}"; }
            }
            catch (Exception ex) { EncryptStatus.Text = "DLL_CRASH: " + ex.Message; }
            finally { LockButton.IsEnabled = true; }
        }

        // ── Decrypt ───────────────────────────────────────────────────────────
        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            string path = DecryptPathInput.Text.Trim();
            string key  = DecryptKeyInput.Text.Trim();

            if (string.IsNullOrEmpty(path)) { DecryptStatus.Text = "NO_PATH";         return; }
            if (string.IsNullOrEmpty(key))  { DecryptStatus.Text = "NO_KEY_PROVIDED"; return; }

            bool isFolder = Directory.Exists(path);
            bool isFile   = File.Exists(path);

            if (!isFolder && !isFile) { DecryptStatus.Text = "INVALID_PATH"; return; }

            DecryptStatus.Text = "DECRYPTING...";
            UnlockButton.IsEnabled = false;

            try
            {
                int result = isFolder
                    ? decrypt_folder(path, key)
                    : decrypt_file(path, key);

                DecryptStatus.Text = result == 0 ? "SUCCESS" : $"ERR_CODE: {result}";

                if (result == 0)
                    AddHistoryEntry(new HistoryEntry
                    {
                        Type = isFolder ? "Folder Decrypted" : "File Decrypted",
                        Path = path,
                        Key  = key,
                        Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    });
            }
            catch (Exception ex) { DecryptStatus.Text = "DLL_CRASH: " + ex.Message; }
            finally { UnlockButton.IsEnabled = true; }
        }

        // ── Generate standalone key ───────────────────────────────────────────
        private void GenerateKey_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                var keyBuf = new StringBuilder(512);
                int result = generate_key(keyBuf, keyBuf.Capacity);

                if (result == 0)
                {
                    string key = keyBuf.ToString();
                    GeneratedKeyBox.Text = key;
                    GeneratedKeyPanel.Visibility = Visibility.Visible;

                    AddHistoryEntry(new HistoryEntry
                    {
                        Type = "Key Generated",
                        Path = "—",
                        Key  = key,
                        Date = DateTime.Now.ToString("yyyy-MM-dd HH:mm")
                    });
                }
                else { EncryptStatus.Text = $"KEYGEN_ERR: {result}"; }
            }
            catch (Exception ex) { EncryptStatus.Text = "DLL_CRASH: " + ex.Message; }
        }

        // ── Copy / paste ──────────────────────────────────────────────────────
        private void CopyKey_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(KeyOutputBox.Text))
            {
                Clipboard.SetText(KeyOutputBox.Text);
                EncryptStatus.Text = "KEY_COPIED";
            }
        }

        private void CopyGeneratedKey_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(GeneratedKeyBox.Text))
                Clipboard.SetText(GeneratedKeyBox.Text);
        }

        private void PasteKey_Click(object sender, RoutedEventArgs e)
        {
            if (Clipboard.ContainsText())
                DecryptKeyInput.Text = Clipboard.GetText();
        }

        // ── Copy key from history card ────────────────────────────────────────
        private void CopyHistoryKey_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string key)
                Clipboard.SetText(key);
        }
        // ── Remove single history entry ───────────────────────────────────────────
        private void RemoveHistoryEntry_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string id)
            {
                _history.RemoveAll(h => h.Id == id);
                SaveHistory();
                RefreshHistoryUI();
            }
        }

        // ── Use key from history (paste into decrypt page) ────────────────────
        private void UseHistoryKey_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string key)
            {
                DecryptKeyInput.Text = key;
                ShowPage(PageDecrypt);
                TabDecrypt.IsChecked = true;
            }
        }

        // ── Clear history ─────────────────────────────────────────────────────
        private void ClearHistory_Click(object sender, RoutedEventArgs e)
        {
            var confirm = MessageBox.Show(
                "This will permanently delete all saved keys. Continue?",
                "Clear history", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (confirm != MessageBoxResult.Yes) return;
            _history.Clear();
            SaveHistory();
            RefreshHistoryUI();
        }

        // ── Navigation ────────────────────────────────────────────────────────
        private void ShowPage(UIElement page)
        {
            PageEncrypt.Visibility  = Visibility.Collapsed;
            PageDecrypt.Visibility  = Visibility.Collapsed;
            PageHistory.Visibility  = Visibility.Collapsed;
            PageSettings.Visibility = Visibility.Collapsed;
            PageAbout.Visibility    = Visibility.Collapsed;
            page.Visibility         = Visibility.Visible;
        }

        private void Nav_Encrypt(object sender, RoutedEventArgs e)  { ShowPage(PageEncrypt);  TabEncrypt.IsChecked  = true; }
        private void Nav_Decrypt(object sender, RoutedEventArgs e)  { ShowPage(PageDecrypt);  TabDecrypt.IsChecked  = true; }
        private void Nav_History(object sender, RoutedEventArgs e)  { ShowPage(PageHistory);  TabHistory.IsChecked  = true; }
        private void Nav_Settings(object sender, RoutedEventArgs e) { ShowPage(PageSettings); TabSettings.IsChecked = true; }
        private void Nav_About(object sender, RoutedEventArgs e)    { ShowPage(PageAbout);    TabAbout.IsChecked    = true; }

        // ── Theme ─────────────────────────────────────────────────────────────
        private void ThemeToggle_Click(object sender, RoutedEventArgs e)
        {
            _isDark = !_isDark;
            ApplyTheme(_isDark);
            SaveSettings();
        }

        private void ThemeCombo_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (ThemeCombo == null) return;
            _isDark = ThemeCombo.SelectedIndex == 1;
            ApplyTheme(_isDark);
            SaveSettings();
        }

        private void ApplyTheme(bool dark)
        {
            var res = this.Resources;
            if (dark)
            {
                res["BgMain"]      = Brush("#1E1E1C"); res["BgSurface"]   = Brush("#252523");
                res["BgCard"]      = Brush("#2C2C2A"); res["BorderColor"] = Brush("#3A3A38");
                res["TextPrimary"] = Brush("#F0EFE9"); res["TextMuted"]   = Brush("#888780");
                res["ActiveBg"]    = Brush("#F0EFE9"); res["ActiveFg"]    = Brush("#1E1E1C");
                ThemeIcon.Text = "\uE706"; ThemeLabel.Text = "Light mode";
            }
            else
            {
                res["BgMain"]      = Brush("#F5F4F0"); res["BgSurface"]   = Brush("#ECEAE4");
                res["BgCard"]      = Brush("#FFFFFF"); res["BorderColor"] = Brush("#D3D1C7");
                res["TextPrimary"] = Brush("#2C2C2A"); res["TextMuted"]   = Brush("#888780");
                res["ActiveBg"]    = Brush("#2C2C2A"); res["ActiveFg"]    = Brush("#F5F4F0");
                ThemeIcon.Text = "\uE708"; ThemeLabel.Text = "Dark mode";
            }
            if (ThemeCombo != null) ThemeCombo.SelectedIndex = dark ? 1 : 0;
        }

        private System.Windows.Media.SolidColorBrush Brush(string hex) =>
            new((System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex));

        // ── Window controls ───────────────────────────────────────────────────
        private void Fullscreen_Click(object sender, RoutedEventArgs e) =>
            WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
        private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;
        private void Close_Click(object sender, RoutedEventArgs e) => Close();

        private void Window_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
        {
            if (e.Key != System.Windows.Input.Key.Enter) return;
            if (PageEncrypt.Visibility == Visibility.Visible) LockButton_Click(sender, e);
            else if (PageDecrypt.Visibility == Visibility.Visible) UnlockButton_Click(sender, e);
        }
    }
}