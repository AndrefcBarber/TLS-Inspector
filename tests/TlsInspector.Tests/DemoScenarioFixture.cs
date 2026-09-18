using TlsInspector.Core.Demo;

namespace TlsInspector.Tests;

/// <summary>Starts the loopback scenario servers once for the whole test class.</summary>
public sealed class DemoScenarioFixture : IAsyncLifetime
{
    public DemoScenarioHost Host { get; } = new();

    public Task InitializeAsync()
    {
        Host.Start();
        return Task.CompletedTask;
    }

    public async Task DisposeAsync() => await Host.DisposeAsync();

    public DemoScenario Scenario(string id) =>
        Host.Find(id) ?? throw new InvalidOperationException($"Scenario '{id}' is not registered.");
}
