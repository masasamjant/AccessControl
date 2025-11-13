namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents secret data associated with a user.
    /// </summary>
    public interface IUserSecret
    {
        /// <summary>
        /// Gets the type of the secret.
        /// </summary>
        UserSecretType SecretType { get; }

        /// <summary>
        /// Gets the secret data.
        /// </summary>
        byte[] Data { get; }
    }
}
