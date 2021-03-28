namespace WebApi.Helpers
{
    public class AppSettings
    {
        //Tiempo de vida del token en días, los inactivos son borrados despues de ese tiempo
        public string Secret { get; set; }
        public int RefreshTokenTTL { get; set; }
        public string EmailFrom { get; set; }
        public string SmtpHost { get; set; }
        public int SmtpPort { get; set; }
        public string SmtpUser { get; set; }
        public string SmtpPass { get; set; }
    }
}