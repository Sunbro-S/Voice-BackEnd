using Infrastructure.Data.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Infrastructure;

public class ContextDb : IdentityDbContext
{
    public ContextDb(DbContextOptions<ContextDb> options) : base(options)
    {
    }

    public DbSet<UserEntity> Users { get; set; }
    public DbSet<FriendLists> FriendLists { get; set; }
    public DbSet<ExtendedIdentityUser> ExtendedIdentityUsers { get; set; }
}