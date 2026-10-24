using System.Windows;
using System.Windows.Controls;
using MVTC.App.Services;

namespace MVTC.App.Views;

public partial class DashboardPanel : UserControl
{
    public DashboardPanel()
    {
        InitializeComponent();
        Loaded += (_, _) =>
        {
            LoadFromState();
            LayoutService.Changed += OnLayoutChanged;
            ApplyLayout();
        };
        Unloaded += (_, _) => LayoutService.Changed -= OnLayoutChanged;
    }

    public void LoadFromState()
    {
        LayoutMission.Refresh();
        LayoutWorkspace.Refresh();
    }

    private void OnLayoutChanged()
    {
        ApplyLayout();
        LoadFromState();
    }

    private void ApplyLayout()
    {
        var k = LayoutService.Current;
        LayoutMission.Visibility   = k == LayoutService.Kind.OperatorMissionControl ? Visibility.Visible : Visibility.Collapsed;
        LayoutWorkspace.Visibility = k == LayoutService.Kind.SaasWorkspace          ? Visibility.Visible : Visibility.Collapsed;
    }
}
