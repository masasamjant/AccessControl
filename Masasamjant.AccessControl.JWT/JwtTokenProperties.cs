namespace Masasamjant.AccessControl
{
    /// <summary>
    /// Properties for JWT token generation and validation. 
    /// </summary>
    public sealed class JwtTokenProperties : ICloneable, IAuthored
    {
        private JwtSecurityAlgorithm signAlgorithm = JwtSecurityAlgorithm.None;
        private JwtSecurityAlgorithm encryptKeyWrapAlgorithm = JwtSecurityAlgorithm.None;
        private JwtSecurityAlgorithm encryptAlgorithm = JwtSecurityAlgorithm.None;
        private int tokenExpiryInMinutes = 90;

        /// <summary>
        /// Initializes new instance of the <see cref="JwtTokenProperties"/> class.
        /// </summary>
        /// <param name="authority">The authority.</param>
        public JwtTokenProperties(Authority authority)
        {
            Authority = authority;
        }

        /// <summary>
        /// Gets the authority of the properties and token.
        /// </summary>
        public Authority Authority { get; }

        /// <summary>
        /// Gets or sets the signing key.
        /// </summary>
        public string SignKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the signing algorithm.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If <c>value</c> is not defined.</exception>
        public JwtSecurityAlgorithm SignAlgorithm 
        { 
            get { return signAlgorithm; }
            set
            {
                if (!Enum.IsDefined(value))
                    throw new ArgumentOutOfRangeException(nameof(SignAlgorithm), value, "The specified signing algorithm is not defined.");

                this.signAlgorithm = value;
            }
        }

        /// <summary>
        /// Gets a value indicating whether the token is signed.
        /// </summary>
        public bool IsSigned
        {
            get { return !string.IsNullOrWhiteSpace(SignKey) && SignAlgorithm != JwtSecurityAlgorithm.None; }
        }

        /// <summary>
        /// Gets or sets the encryption key.
        /// </summary>
        public string EncryptKey { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the encryption key wrap algorithm.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If <c>value</c> is not defined.</exception>
        public JwtSecurityAlgorithm EncryptKeyWrapAlgorithm
        {
            get { return encryptKeyWrapAlgorithm; }
            set
            {
                if (!Enum.IsDefined(value))
                    throw new ArgumentOutOfRangeException(nameof(EncryptKeyWrapAlgorithm), value, "The specified encryption key wrap algorithm is not defined.");
                this.encryptKeyWrapAlgorithm = value;

            }
        }

        /// <summary>
        /// Gets or sets the encryption algorithm.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If <c>value</c> is not defined.</exception>
        public JwtSecurityAlgorithm EncryptAlgorithm
        {
            get { return encryptAlgorithm; }
            set
            {
                if (!Enum.IsDefined(value))
                    throw new ArgumentOutOfRangeException(nameof(EncryptAlgorithm), value, "The specified encryption algorithm is not defined.");
                this.encryptAlgorithm = value;
            }
        }
        
        /// <summary>
        /// Gets a value indicating whether the token is encrypted.
        /// </summary>
        public bool IsEncrypted
        {
            get
            {
                return !string.IsNullOrWhiteSpace(EncryptKey)
                    && EncryptKeyWrapAlgorithm != JwtSecurityAlgorithm.None
                    && EncryptAlgorithm != JwtSecurityAlgorithm.None;
            }
        }

        /// <summary>
        /// Gets or sets the audience. If empty string or only whitespace, the authority name is used as audience.
        /// </summary>
        public string Audience { get; } = string.Empty;

        /// <summary>
        /// Gets or sets the token expiry in minutes.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">If <c>value</c> is less than or equal to zero.</exception>
        public int TokenExpiryInMinutes
        {
            get { return tokenExpiryInMinutes; }
            set
            {
                if (value <= 0)
                    throw new ArgumentOutOfRangeException(nameof(TokenExpiryInMinutes), value, "Token expiry must be greater than zero minutes.");

                tokenExpiryInMinutes = value;
            }
        }

        /// <summary>
        /// Creates a clone of the current <see cref="JwtTokenProperties"/> instance.
        /// </summary>
        /// <returns>A copy of the current instance.</returns>
        public JwtTokenProperties Clone()
        {
            var authority = new Authority(Authority.Uri, Authority.Name);
            return new JwtTokenProperties(authority)
            {
                SignKey = SignKey,
                SignAlgorithm = SignAlgorithm,
                EncryptKey = EncryptKey,
                EncryptKeyWrapAlgorithm = EncryptKeyWrapAlgorithm,
                EncryptAlgorithm = EncryptAlgorithm,
                TokenExpiryInMinutes = TokenExpiryInMinutes
            };
        }

        object ICloneable.Clone()
        {
            return Clone();
        }
    }
}
