using DatingApp.API.Data;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections;
using System.Threading.Tasks;

public class AuthRepository : IAuthRepository
{
    private readonly DataContext _context;

	public AuthRepository(DataContext context)
	{
        _context = context;
	}

    public async Task<User> Login(string username, string password)
    {
        var user = await _context.Users.FirstOrDefaultAsync(x => x.UserName == username);

        if (user == null)
            return null;
      
        if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt))
            return null;

        return user;

    }

    private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
    {
        using (var hmac = new System.Security.Cryptography.HMACSHA512(passwordSalt))
        {
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));

            return StructuralComparisons.StructuralEqualityComparer.Equals(passwordHash, computedHash);

        }

    }

    public async Task<User> Register(User user, string password)
    {
        byte[] PasswordHash, PasswordSalt;

        CreatePasswordHash(password, out PasswordHash, out PasswordSalt);

        user.PasswordHash = PasswordHash;
        user.PasswordSalt = PasswordSalt;

        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();

        return user;
    }

    private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
    {
        using (var hmac = new System.Security.Cryptography.HMACSHA512())
        {
            passwordHash = hmac.Key;
            passwordSalt = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
        }    
    }

    public async Task<bool> UserExists(string username)
    {
        if (await _context.Users.AnyAsync(x => x.UserName == username))        
            return true;
        
        return false;
        
    }
}
