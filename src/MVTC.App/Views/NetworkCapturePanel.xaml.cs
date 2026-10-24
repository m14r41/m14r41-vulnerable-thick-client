using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using MVTC.Core.Services;

namespace MVTC.App.Views;

public partial class NetworkCapturePanel : UserControl
{
    private readonly ObservableCollection<EntryRow> _rows = new();

    public NetworkCapturePanel()
    {
        InitializeComponent();
        Entries.ItemsSource = _rows;
        Loaded += (_, _) => Refresh();
    }

    public void Refresh()
    {
        _rows.Clear();
        foreach (var e in HttpCapture.Snapshot())
            _rows.Add(new EntryRow(e));
    }

    private void OnRefresh(object sender, RoutedEventArgs e) => Refresh();

    private void OnClear(object sender, RoutedEventArgs e)
    {
        HttpCapture.Clear();
        _rows.Clear();
        RequestBox.Text = "";
        ResponseBox.Text = "";
        DetailHeader.Text = "capture cleared";
    }

    private void OnEntrySelected(object sender, SelectionChangedEventArgs e)
    {
        if (Entries.SelectedItem is not EntryRow row) return;
        DetailHeader.Text = $"{row.Method} {row.Url}   ·   {row.StatusCode}   ·   {row.Entry.DurationMs} ms";
        RequestBox.Text  = row.Entry.RequestBody ?? "(no request body)";
        ResponseBox.Text = row.Entry.ResponseBody ?? "(no response body)";
    }

    public sealed class EntryRow
    {
        public CaptureEntry Entry { get; }
        public EntryRow(CaptureEntry e) { Entry = e; }
        public string TimeDisplay => Entry.Timestamp.ToString("HH:mm:ss");
        public string Method      => Entry.Method;
        public string Url         => Entry.Url;
        public string StatusCode  => Entry.StatusCode?.ToString() ?? "-";
    }
}
