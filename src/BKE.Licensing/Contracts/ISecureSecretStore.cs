namespace BKE.Licensing.Contracts;

public interface ISecureSecretStore
{
    void WriteSecret(string name, ReadOnlySpan<byte> secret);
    byte[]? ReadSecret(string name);
    void DeleteSecret(string name);
}

public sealed class SecureSecretStorageException : Exception
{
    public SecureSecretStorageException()
    {
    }

    public SecureSecretStorageException(string message)
        : base(message)
    {
    }

    public SecureSecretStorageException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
