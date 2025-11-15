namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Represents provider of JWT token properties.
    /// </summary>
    public interface IJwtTokenPropertiesProvider
    {
        /// <summary>
        /// Gets the JWT token properties for specified authority.
        /// </summary>
        /// <param name="authority">The authority to get parameters.</param>
        /// <returns>A <see cref="JwtTokenProperties"/>.</returns>
        JwtTokenProperties GetJWTProperties(Authority authority);
    }
}
