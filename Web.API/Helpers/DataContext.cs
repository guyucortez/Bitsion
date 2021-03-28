using Microsoft.EntityFrameworkCore;
using WebApi.Entities;

namespace WebApi.Helpers
{
    public class DataContext : DbContext
    {
        public DbSet<Account> Accounts { get; set; }
        
        public DataContext(DbContextOptions<DataContext> options)
            : base(options)
        {
        }
    }
}