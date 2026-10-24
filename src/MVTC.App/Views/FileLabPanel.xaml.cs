using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using MVTC.Core.Services.Vuln;

namespace MVTC.App.Views;

public partial class FileLabPanel : UserControl
{
    private string _installRoot = "";
    private ArchiveService? _archive;
    private HelpService? _help;
    private FileService? _file;
    private ImportService? _import;
    private XmlImportService? _xml;
    private readonly ObservableCollection<LibraryEntry> _library = new();

    public FileLabPanel()
    {
        InitializeComponent();
        LibraryGrid.ItemsSource = _library;
    }

    public void Attach(string installRoot)
    {
        _installRoot = installRoot;
        _archive = new ArchiveService();
        _help = new HelpService();
        _file = new FileService(Path.Combine(installRoot, "reports"));
        _import = new ImportService(installRoot);
        _xml = new XmlImportService();

        // Only the zip sample is pre-filled (a learner needs to see something
        // real to understand "archive extractor"); the attack-shaped paths
        // (CHM, deserialization gadget, XXE payload, custom report path) stay
        // blank so the tester has to craft or find them.
        ZipPath.Text   = Path.Combine(installRoot, "samples", "zipslip.zip");

        RefreshLibrary();
    }

    private void RefreshLibrary()
    {
        _library.Clear();
        var startup = Path.Combine(_installRoot, "Startup");
        if (!Directory.Exists(startup)) return;
        foreach (var f in Directory.GetFiles(startup))
        {
            var fi = new FileInfo(f);
            _library.Add(new LibraryEntry { Name = fi.Name, Length = fi.Length, Path = fi.FullName });
        }
    }

    // ---- Drag-drop upload ----

    private void OnDragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            DropZone.Background = System.Windows.Media.Brushes.Transparent;
            DropZone.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x58, 0xA6, 0xFF));
            DropHint.Text = "release to upload";
        }
        else e.Effects = DragDropEffects.None;
    }

    private void OnDragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
    }

    private void OnDragLeave(object sender, DragEventArgs e)
    {
        DropZone.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x30, 0x36, 0x3D));
        DropHint.Text = "or";
    }

    private void OnDrop(object sender, DragEventArgs e)
    {
        DropZone.BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x30, 0x36, 0x3D));
        DropHint.Text = "or";
        if (!e.Data.GetDataPresent(DataFormats.FileDrop)) return;
        var paths = (string[])e.Data.GetData(DataFormats.FileDrop);
        foreach (var p in paths) UploadFile(p, Path.GetFileName(p));
    }

    private void OnBrowse(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog { Multiselect = true };
        if (dlg.ShowDialog() != true) return;
        foreach (var p in dlg.FileNames) UploadFile(p, Path.GetFileName(p));
    }

    private void UploadFile(string sourcePath, string suggestedName)
    {
        if (_import is null) return;
        try
        {
            var bytes = File.ReadAllBytes(sourcePath);
            var written = _import.ImportProfile(suggestedName, bytes);
            // Trigger the autorun scanner - if a .pwn file is now in Startup,
            // it writes the recovery token to the audit log. We don't surface
            // the token in the UI; the tester has to read audit.log.
            var autorun = _import.ReadAutorunFlag(Path.Combine(_installRoot, "flags"));
            if (autorun is not null)
                App.Logger?.Write("WARN", "autorun", $"profile scan matched a startup trigger; recovery_token={autorun}");
            UploadStatus.Text = $"uploaded: {written}";
            RefreshLibrary();
        }
        catch (Exception ex) { UploadStatus.Text = ex.Message; }
    }

    // ---- Other operations (unchanged mechanic) ----

    private void OnExtractZip(object sender, RoutedEventArgs e)
    {
        if (_archive is null) return;
        try
        {
            var dest = Path.Combine(_installRoot, "extracted");
            var files = _archive.Extract(ZipPath.Text.Trim(), dest);
            ZipOut.Text = $"wrote {files.Count} file(s). Last resolved path(s):\n  " + string.Join("\n  ", files);
        }
        catch (Exception ex) { ZipOut.Text = ex.Message; }
    }

    private void OnOpenHelp(object sender, RoutedEventArgs e)
    {
        if (_help is null) return;
        try
        {
            var path = HelpPath.Text.Trim();
            if (File.Exists(path) && Path.GetExtension(path).ToLowerInvariant() != ".chm")
            {
                HelpOut.Text = File.ReadAllText(path);
                return;
            }
            var r = _help.OpenHelp(path);
            HelpOut.Text = $"exit={r.ExitCode}\n{r.Output}";
        }
        catch (Exception ex) { HelpOut.Text = ex.Message; }
    }

    private void OnReadReport(object sender, RoutedEventArgs e)
    {
        if (_file is null) return;
        try { ReportOut.Text = _file.ReadReport(ReportPath.Text.Trim()); }
        catch (Exception ex) { ReportOut.Text = ex.Message; }
    }

    private void OnImportState(object sender, RoutedEventArgs e)
    {
        if (_import is null) return;
        try { StateOut.Text = _import.ImportState(StatePath.Text.Trim()); }
        catch (Exception ex) { StateOut.Text = ex.Message; }
    }

    private void OnImportXml(object sender, RoutedEventArgs e)
    {
        if (_xml is null) return;
        try { XmlOut.Text = _xml.ImportAndRender(XmlPath.Text.Trim()); }
        catch (Exception ex) { XmlOut.Text = ex.Message; }
    }

    public sealed class LibraryEntry
    {
        public string Name { get; set; } = "";
        public long   Length { get; set; }
        public string Path { get; set; } = "";
    }
}
