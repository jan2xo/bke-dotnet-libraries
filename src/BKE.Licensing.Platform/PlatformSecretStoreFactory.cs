using BKE.Licensing.Contracts;
using BKE.Licensing.Platform.MacOS;
using BKE.Licensing.Platform.Windows;

namespace BKE.Licensing.Platform;

public static class PlatformSecretStoreFactory
{
    public static ISecureSecretStore CreateForCurrentPlatform(
        string storeDirectory,
        string scopeName,
        string? macOsKeychainPath = null)
    {
        if (OperatingSystem.IsWindows())
        {
            return new WindowsDpapiSecretStore(storeDirectory, scopeName);
        }

        if (OperatingSystem.IsMacOS())
        {
            return new MacOsKeychainSecretStore(storeDirectory, scopeName, macOsKeychainPath);
        }

        throw new PlatformNotSupportedException(
            "Secure secret storage requires Windows DPAPI or macOS Keychain.");
    }
}
