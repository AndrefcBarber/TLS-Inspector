namespace TlsInspector.Core;

/// <summary>
/// RFC 6125 style name matching, reimplemented so the inspector can explain <em>why</em> a
/// certificate does or does not cover the host that was requested.
/// </summary>
public static class HostnameMatcher
{
    public static bool Matches(string certificateName, string host)
    {
        if (string.IsNullOrWhiteSpace(certificateName) || string.IsNullOrWhiteSpace(host))
        {
            return false;
        }

        var name = certificateName.Trim().TrimEnd('.');
        var target = host.Trim().TrimEnd('.');

        if (!name.StartsWith("*.", StringComparison.Ordinal))
        {
            return string.Equals(name, target, StringComparison.OrdinalIgnoreCase);
        }

        // A wildcard only covers a single label, and only the left-most one.
        var suffix = name[2..];
        var separator = target.IndexOf('.');
        if (separator <= 0 || suffix.Length == 0)
        {
            return false;
        }

        var label = target[..separator];
        var remainder = target[(separator + 1)..];
        return label.Length > 0 && string.Equals(suffix, remainder, StringComparison.OrdinalIgnoreCase);
    }

    public static bool MatchesAny(IEnumerable<string> certificateNames, string host) =>
        certificateNames.Any(name => Matches(name, host));
}
