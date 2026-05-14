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
        public string Type      { get; set; } = "";   // "Encrypted" | "Key Generated"
        public string Path      { get; set; } = "";
        public string Algorithm { get; set; } = "ChaCha20-Poly1305";
        public string Key       { get; set; } = "";
        public string Date      { get; set; } = "";
    }

    public partial class MainWindow : Window
    {
        // ── DLL imports ──────────────────────────────────────────────────────
        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int encrypt_folder(string folder, StringBuilder keyOut, int bufLen);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int decrypt_folder(string folder, string base64Key);

        [DllImport("bazingaDlls.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int generate_key(StringBuilder keyOut, int bufLen);

        // ── State ────────────────────────────────────────────────────────────
        private bool _isDark = false;
        private string _lastKey = "";
        private List<HistoryEntry> _history = new();

        private static readonly string HistoryPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "BazingaVault", "history.json");

        public MainWindow()
        {
            InitializeComponent();
            LoadHistory();
        }

        // ── History persistence ──────────────────────────────────────────────
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
            _history.Insert(0, entry); // newest first
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

        // ── Browse (encrypt page) ────────────────────────────────────────────
        private void BrowseEncrypt_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Select Folder to Encrypt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dialog.ShowDialog() == true)
            {
                EncryptPathInput.Text = dialog.FolderName;
                EncryptStatus.Text = "FOLDER_READY";
            }
        }

        // ── Browse (decrypt page) ────────────────────────────────────────────
        private void BrowseDecrypt_Click(object sender, RoutedEventArgs e)
        {
            var dialog = new OpenFolderDialog
            {
                Title = "Select Folder to Decrypt",
                InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments)
            };
            if (dialog.ShowDialog() == true)
            {
                DecryptPathInput.Text = dialog.FolderName;
                DecryptStatus.Text = "FOLDER_READY";
            }
        }

        // ── Encrypt ──────────────────────────────────────────────────────────
        private void LockButton_Click(object sender, RoutedEventArgs e)
        {
            string path = EncryptPathInput.Text;
            if (!Directory.Exists(path)) { EncryptStatus.Text = "INVALID_PATH"; return; }

            EncryptStatus.Text = "ENCRYPTING...";
            LockButton.IsEnabled = false;

            try
            {
                var keyBuf = new StringBuilder(512);
                int result = encrypt_folder(path, keyBuf, keyBuf.Capacity);

                if (result == 0)
                {
                    _lastKey = keyBuf.ToString();
                    KeyOutputBox.Text = _lastKey;
                    KeyOutputPanel.Visibility = Visibility.Visible;
                    EncryptStatus.Text = "SUCCESS — save your key!";

                    AddHistoryEntry(new HistoryEntry
                    {
                        Type = "Encrypted",
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

        // ── Decrypt ──────────────────────────────────────────────────────────
        private void UnlockButton_Click(object sender, RoutedEventArgs e)
        {
            string path = DecryptPathInput.Text;
            string key  = DecryptKeyInput.Text.Trim();

            if (!Directory.Exists(path))      { DecryptStatus.Text = "INVALID_PATH";    return; }
            if (string.IsNullOrEmpty(key))     { DecryptStatus.Text = "NO_KEY_PROVIDED"; return; }

            DecryptStatus.Text = "DECRYPTING...";
            UnlockButton.IsEnabled = false;

            try
            {
                int result = decrypt_folder(path, key);
                DecryptStatus.Text = result == 0 ? "SUCCESS" : $"ERR_CODE: {result}";
            }
            catch (Exception ex) { DecryptStatus.Text = "DLL_CRASH: " + ex.Message; }
            finally { UnlockButton.IsEnabled = true; }
        }

        // ── Generate standalone key ──────────────────────────────────────────
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

        // ── Copy / paste ─────────────────────────────────────────────────────
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

        // ── Copy key from history card ───────────────────────────────────────
        private void CopyHistoryKey_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string key)
                Clipboard.SetText(key);
        }

        // ── Use key from history (paste into decrypt page) ───────────────────
        private void UseHistoryKey_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string key)
            {
                DecryptKeyInput.Text = key;
                ShowPage(PageDecrypt);
                TabDecrypt.IsChecked = true;
            }
        }

        // ── Clear history ────────────────────────────────────────────────────
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

        // ── Navigation ───────────────────────────────────────────────────────
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

        // ── Theme ────────────────────────────────────────────────────────────
        private void ThemeToggle_Click(object sender, RoutedEventArgs e) { _isDark = !_isDark; ApplyTheme(_isDark); }

        private void ThemeCombo_Changed(object sender, SelectionChangedEventArgs e)
        {
            if (ThemeCombo == null) return;
            _isDark = ThemeCombo.SelectedIndex == 1;
            ApplyTheme(_isDark);
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

        // ── Window controls ──────────────────────────────────────────────────
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